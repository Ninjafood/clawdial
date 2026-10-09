#!/usr/bin/env python3
"""OpenClaw Model Control — a small, dependency-free control panel for OpenClaw models.

Standard library only (no pip/npm). Listens on 0.0.0.0, but only answers LAN/Tailscale
clients, requires a password, and never trusts proxy headers.

Usage:
  server.py                 run the server (port 8790)
  server.py --set-password  set/replace the login password
"""
import getpass
import re
import shutil
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("MODEL_UI_DATA", HERE)          # where auth/state/sessions live

DEFAULTS = {
    "port": 8790,
    "openclaw_bin": "openclaw",                            # name on PATH or absolute path
    "openclaw_home": "~/.openclaw",                        # holds openclaw.json and .env
    "allowed_cidrs": [                                     # who may connect at all
        "127.0.0.0/8", "::1/128",
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # private LANs
        "100.64.0.0/10", "fd7a:115c:a1e0::/48",            # Tailscale
    ],
    "backend_hint": {},                                    # provider id -> unsloth|lmstudio|ollama|generic (optional)
    "gateway_restart_cmd": "",                             # optional shell command to restart the gateway (e.g. systemctl --user restart openclaw)
    "gateway_launchd_label": "ai.openclaw.gateway",       # macOS fallback when the openclaw CLI refuses
}


def load_config():
    cfg = dict(DEFAULTS)
    path = os.environ.get("MODEL_UI_CONFIG", os.path.join(DATA_DIR, "config.json"))
    try:
        with open(path) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    cfg["port"] = int(os.environ.get("MODEL_UI_PORT", cfg["port"]))
    cfg["openclaw_home"] = os.path.expanduser(os.environ.get("OPENCLAW_HOME", cfg["openclaw_home"]))
    cfg["openclaw_bin"] = os.environ.get("OPENCLAW_BIN", cfg["openclaw_bin"])
    return cfg


CFG = load_config()
OC_HOME = CFG["openclaw_home"]
OC_CONFIG = os.environ.get("OPENCLAW_CONFIG", os.path.join(OC_HOME, "openclaw.json"))
OC_ENV = os.path.join(OC_HOME, ".env")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
STATE_FILE = os.path.join(DATA_DIR, "state.json")
PORT = CFG["port"]
SESSION_TTL = 7 * 24 * 3600
ENV_PATH = os.environ.get("PATH", "") + ":/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
OPENCLAW = CFG["openclaw_bin"] if os.path.isabs(CFG["openclaw_bin"]) else (shutil.which(CFG["openclaw_bin"], path=ENV_PATH) or CFG["openclaw_bin"])
ALLOWED_NETS = [ipaddress.ip_network(n) for n in CFG["allowed_cidrs"]]
PROXY_HEADERS = ("x-forwarded-for", "cf-connecting-ip", "x-real-ip", "forwarded", "cf-ray")

LOCK = threading.Lock()
FAILED_LOGINS = {}     # ip -> [timestamps]


# ---------------------------------------------------------------- helpers

def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_state():
    st = read_json(STATE_FILE, {})
    st.setdefault("schedules", [])
    st.setdefault("log", [])
    st.setdefault("lastRun", {})
    return st


def log_event(msg):
    with LOCK:
        st = load_state()
        st["log"].insert(0, {"t": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "msg": msg})
        st["log"] = st["log"][:300]
        write_json(STATE_FILE, st)


def env_secrets():
    out = {}
    try:
        with open(OC_ENV) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def resolve_key(api_key):
    if isinstance(api_key, str):
        return api_key
    if isinstance(api_key, dict) and api_key.get("source") == "env":
        return env_secrets().get(api_key.get("id", ""), "") or os.environ.get(api_key.get("id", ""), "")
    return ""


def oc_config():
    return read_json(OC_CONFIG, {})


def apply_patch(patch, why, extra_args=()):
    """Apply a config patch through OpenClaw's own validated patch command."""
    fd, tmp = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(patch, f)
    try:
        r = subprocess.run([OPENCLAW, "config", "patch", "--file", tmp, *extra_args], capture_output=True,
                           text=True, timeout=120, env={**os.environ, "PATH": ENV_PATH})
    finally:
        os.unlink(tmp)
    out = (r.stdout + r.stderr).strip().splitlines()
    ok = r.returncode == 0 and not any("error" in l.lower() and "applied" not in l.lower() for l in out[-3:])
    log_event(("✅ " if ok else "❌ ") + why + ("" if ok else " — " + " ".join(out[-2:])))
    return ok, "\n".join(out[-4:])


def http_json(url, method="GET", body=None, key="", timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", "Bearer " + key)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode() or "{}"
        return json.loads(raw)


# ---------------------------------------------------------------- OpenClaw views

def provider_info(cfg, name):
    p = cfg.get("models", {}).get("providers", {}).get(name, {})
    base = p.get("baseUrl", "")
    return base, resolve_key(p.get("apiKey"))


def lp(cfg=None):
    """Id of the local provider (Unsloth / LM Studio / Ollama) or None."""
    return local_provider(cfg or oc_config())


def local_models(cfg):
    name = lp(cfg)
    return name, (list(cfg["models"]["providers"][name]["models"]) if name else [])


def model_catalog(cfg):
    out = []
    for pname, p in cfg.get("models", {}).get("providers", {}).items():
        for i, m in enumerate(p.get("models", [])):
            out.append({
                "ref": "%s/%s" % (pname, m["id"]), "provider": pname, "id": m["id"], "index": i,
                "name": m.get("name", m["id"]), "contextWindow": m.get("contextWindow"),
                "maxTokens": m.get("maxTokens"), "baseUrl": p.get("baseUrl", ""),
                "input": m.get("input", ["text"]), "reasoning": bool(m.get("reasoning")),
            })
    return out


def agents_view(cfg):
    defaults = cfg.get("agents", {}).get("defaults", {})
    dm = defaults.get("model")
    d_primary = dm.get("primary") if isinstance(dm, dict) else dm
    d_fallbacks = dm.get("fallbacks", []) if isinstance(dm, dict) else []
    rows = []
    for aid, e in cfg.get("agents", {}).get("entries", {}).items():
        m = e.get("model")
        primary = m.get("primary") if isinstance(m, dict) else m
        fallbacks = m.get("fallbacks", []) if isinstance(m, dict) else []
        ident = e.get("identity", {}) or {}
        rows.append({
            "id": aid, "name": ident.get("name") or e.get("name") or aid, "emoji": ident.get("emoji", ""),
            "model": primary, "inherits": primary is None, "effective": primary or d_primary,
            "fallbacks": fallbacks, "note": e.get("description", ""),
            "thinking": e.get("thinkingDefault") or "", "promptBudget": e.get("bootstrapTotalMaxChars"),
            "toolProfile": ((e.get("tools") or {}).get("profile")) or "", "workspace": e.get("workspace", ""),
            "theme": ident.get("theme", ""),
        })
    return {"default": {"model": d_primary, "fallbacks": d_fallbacks,
                        "thinking": defaults.get("thinkingDefault") or "", "promptBudget": defaults.get("bootstrapTotalMaxChars")},
            "agents": rows}


def desktop_catalog_entry(cfg, model_id):
    """Build a catalog entry for a model the local server has downloaded but OpenClaw doesn't know yet."""
    for m in (CACHE.get("unsloth") or {}).get("models", []):
        if m["id"] == model_id and not m.get("task"):
            us = CACHE.get("unsloth") or {}
            loaded = int(us.get("context") or 0) if us.get("active") == model_id else 0
            ctx = loaded or min(int(m.get("maxContext") or 32768), 131072)
            return {"id": model_id, "name": "%s (desktop)" % model_id, "contextWindow": ctx, "maxTokens": 4096,
                    "input": ["text"], "reasoning": False, "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0}}
    return None


def set_agent_model(agent, model, fallbacks, note, thinking=None, prompt_budget=None):
    cfg = oc_config()
    if agent != "__default__" and agent not in cfg.get("agents", {}).get("entries", {}):
        return False, "unknown agent"
    refs = {m["ref"] for m in model_catalog(cfg)}
    extra = {}
    for r in [model] + list(fallbacks or []):
        if r and r not in refs:
            if lp(cfg) and r.startswith(lp(cfg) + "/"):
                ent = desktop_catalog_entry(cfg, r.split("/", 1)[1])
                if ent:
                    extra[r] = ent
                    continue
            return False, "unknown model " + r
    allow = {r: {} for r in [model] + list(fallbacks or []) if r}
    patch = {"agents": {"defaults": {"models": allow}}}
    if extra:
        name, models = local_models(cfg)
        patch["models"] = {"providers": {name: {"models": models + list(extra.values())}}}
    if agent == "__default__":
        val = {"primary": model, "fallbacks": fallbacks or []}
        patch["agents"]["defaults"]["model"] = val
        if thinking is not None:
            patch["agents"]["defaults"]["thinkingDefault"] = thinking or None
        if prompt_budget is not None:
            patch["agents"]["defaults"]["bootstrapTotalMaxChars"] = int(prompt_budget) if prompt_budget else None
        return apply_patch(patch, "Default model → %s%s" % (model, " (+%d fallbacks)" % len(fallbacks) if fallbacks else ""))
    if not model:
        val = None  # inherit default
    elif fallbacks:
        val = {"primary": model, "fallbacks": fallbacks}
    else:
        val = model
    entry = {"model": val}
    if note is not None:
        entry["description"] = note or None
    if thinking is not None:
        entry["thinkingDefault"] = thinking or None
    if prompt_budget is not None:
        entry["bootstrapTotalMaxChars"] = int(prompt_budget) if prompt_budget else None
    patch["agents"]["entries"] = {agent: entry}
    return apply_patch(patch, "%s → %s%s" % (agent, model or "(inherit default)", (" — " + note) if note else ""))


def add_desktop_model(model_id):
    cfg = oc_config()
    name, models = local_models(cfg)
    if not name:
        return False, "no local model server detected"
    if any(m["ref"] == name + "/" + model_id for m in model_catalog(cfg)):
        return False, "already configured"
    ent = desktop_catalog_entry(cfg, model_id)
    if not ent:
        return False, "the local server doesn't list that model (is it running?)"
    patch = {"models": {"providers": {name: {"models": models + [ent]}}}, "agents": {"defaults": {"models": {name + "/" + model_id: {}}}}}
    return apply_patch(patch, "Added local model %s/%s (context %s)" % (name, model_id, ent["contextWindow"]))


def add_alias(ref, ctx, max_tokens):
    """Copy an unsloth model entry under a new id with a different context (Unsloth serves any name)."""
    cfg = oc_config()
    name = lp(cfg)
    if not name or not ref.startswith(name + "/") or detect_backend(cfg, name) != "unsloth":
        return False, "context copies only work for Unsloth Studio models (it serves any model name)"
    src = next((m for m in model_catalog(cfg) if m["ref"] == ref), None)
    if not src:
        return False, "unknown model"
    base = src["id"].rsplit("-", 1)[0] if src["id"].endswith("k") and "-" in src["id"] else src["id"]
    new_id = "%s-%dk" % (base, int(ctx) // 1000)
    if "@" in new_id:
        return False, "model ids cannot contain @ (OpenClaw reads it as an auth profile)"
    _, models = local_models(cfg)
    if any(m["id"] == new_id for m in models):
        return False, "a copy with that context already exists: %s/%s" % (name, new_id)
    ent = dict(models[src["index"]])
    ent.update({"id": new_id, "name": "%s · %dk context" % (base, int(ctx) // 1000), "contextWindow": int(ctx)})
    if max_tokens:
        ent["maxTokens"] = int(max_tokens)
    models.append(ent)
    patch = {"models": {"providers": {name: {"models": models}}}, "agents": {"defaults": {"models": {name + "/" + new_id: {}}}}}
    ok, msg = apply_patch(patch, "Added %s/%s (context %s)" % (name, new_id, ctx))
    return ok, (name + "/" + new_id) if ok else msg


def set_model_limits(ref, ctx, max_tokens):
    cfg = oc_config()
    for m in model_catalog(cfg):
        if m["ref"] == ref:
            models = list(cfg["models"]["providers"][m["provider"]]["models"])
            entry = dict(models[m["index"]])
            if ctx:
                entry["contextWindow"] = int(ctx)
            if max_tokens:
                entry["maxTokens"] = int(max_tokens)
            models[m["index"]] = entry
            patch = {"models": {"providers": {m["provider"]: {"models": models}}}}
            return apply_patch(patch, "%s context=%s maxTokens=%s" % (ref, entry.get("contextWindow"), entry.get("maxTokens")))
    return False, "unknown model"


# ---------------------------------------------------------------- model + provider catalog editing

PROVIDER_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")
API_KINDS = ("openai-completions", "openai-responses", "anthropic-messages", "ollama")


def _users_of(cfg, ref):
    """Agents (and the default) that use a model ref as primary or fallback."""
    av = agents_view(cfg)
    users = []
    d = av["default"]
    if d["model"] == ref or ref in (d["fallbacks"] or []):
        users.append("default")
    for a in av["agents"]:
        if a["model"] == ref or ref in (a["fallbacks"] or []):
            users.append(a["id"])
    return users


def _models_of(cfg, prov):
    return list(cfg.get("models", {}).get("providers", {}).get(prov, {}).get("models", []))


def _clean_entry(b, existing=None):
    e = dict(existing or {})
    if b.get("name") is not None:
        e["name"] = str(b["name"]).strip() or e.get("id", "")
    if b.get("contextWindow"):
        e["contextWindow"] = int(b["contextWindow"])
    if b.get("maxTokens"):
        e["maxTokens"] = int(b["maxTokens"])
    if b.get("input") is not None:
        inp = [x for x in b["input"] if x in ("text", "image", "audio", "video")] or ["text"]
        e["input"] = inp
    if b.get("reasoning") is not None:
        e["reasoning"] = bool(b["reasoning"])
    e.setdefault("input", ["text"])
    e.setdefault("cost", {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0})
    e.setdefault("reasoning", False)
    return e


def model_add(b):
    prov, mid = str(b.get("provider", "")).strip(), str(b.get("id", "")).strip()
    cfg = oc_config()
    if prov not in cfg.get("models", {}).get("providers", {}):
        return False, "unknown provider"
    if not mid:
        return False, "model id is required"
    if "@" in mid:
        return False, "model ids may not contain @ (OpenClaw reads it as an auth profile)"
    models = _models_of(cfg, prov)
    if any(m["id"] == mid for m in models):
        return False, "that id already exists under this provider"
    e = _clean_entry({**b, "name": b.get("name") or mid})
    e["id"] = mid
    if not e.get("contextWindow"):
        return False, "context is required"
    e.setdefault("maxTokens", 4096)
    models.append(e)
    ref = "%s/%s" % (prov, mid)
    return apply_patch({"models": {"providers": {prov: {"models": models}}}, "agents": {"defaults": {"models": {ref: {}}}}},
                       "➕ Added model %s (context %s)" % (ref, e["contextWindow"]))


def model_update(b):
    ref = str(b.get("ref", ""))
    cfg = oc_config()
    m = next((x for x in model_catalog(cfg) if x["ref"] == ref), None)
    if not m:
        return False, "unknown model"
    models = _models_of(cfg, m["provider"])
    models[m["index"]] = _clean_entry(b, models[m["index"]])
    return apply_patch({"models": {"providers": {m["provider"]: {"models": models}}}}, "✏️ Updated model %s" % ref)


def model_delete(ref):
    cfg = oc_config()
    m = next((x for x in model_catalog(cfg) if x["ref"] == ref), None)
    if not m:
        return False, "unknown model"
    users = _users_of(cfg, ref)
    if users:
        return False, "still used by: %s — change them first" % ", ".join(users)
    models = [x for i, x in enumerate(_models_of(cfg, m["provider"])) if i != m["index"]]
    ok, msg = apply_patch({"models": {"providers": {m["provider"]: {"models": models}}}, "agents": {"defaults": {"models": {ref: None}}}},
                          "🗑️ Removed model %s" % ref, ("--replace-path", "models.providers.%s.models" % m["provider"]))
    return ok, msg


def _write_env_key(name, value):
    lines = []
    try:
        with open(OC_ENV) as f:
            lines = f.read().splitlines()
    except OSError:
        pass
    lines = [l for l in lines if not l.startswith(name + "=")] + ["%s=%s" % (name, value)]
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(OC_ENV))
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, OC_ENV)


def provider_add(b):
    pid = str(b.get("id", "")).strip().lower()
    if not PROVIDER_ID_RE.match(pid):
        return False, "provider id: lowercase letters, digits, dashes/underscores"
    cfg = oc_config()
    if pid in cfg.get("models", {}).get("providers", {}):
        return False, "that provider already exists"
    base = str(b.get("baseUrl", "")).strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        return False, "base URL must start with http:// or https://"
    api = b.get("api") or "openai-completions"
    if api not in API_KINDS:
        return False, "unsupported API kind"
    prov = {"baseUrl": base, "api": api, "models": []}
    key = str(b.get("apiKey") or "").strip()
    restart = False
    if key:
        env_name = re.sub(r"[^A-Z0-9_]", "_", pid.upper()) + "_API_KEY"
        _write_env_key(env_name, key)
        prov["apiKey"] = {"source": "env", "provider": "default", "id": env_name}
        restart = True
    else:
        prov["apiKey"] = "local"
    ok, msg = apply_patch({"models": {"providers": {pid: prov}}}, "➕ Added provider %s (%s, %s)" % (pid, base, api))
    if ok and restart:
        rc, out = run_oc(["gateway", "restart"])
        log_event("♻️ Gateway restarted so it can read the new API key" if rc == 0 else "⚠️ Gateway restart failed: " + out[-120:])
    return ok, msg


def provider_delete(pid):
    cfg = oc_config()
    provs = cfg.get("models", {}).get("providers", {})
    if pid not in provs:
        return False, "unknown provider"
    if provs[pid].get("models"):
        return False, "remove its models first"
    return apply_patch({"models": {"providers": {pid: None}}}, "🗑️ Removed provider %s" % pid)


def provider_test(pid):
    cfg = oc_config()
    base, key = provider_info(cfg, pid)
    if not base:
        return False, {"msg": "unknown provider"}
    t0 = time.time()
    try:
        d = http_json(base.rstrip("/") + "/models", key=key, timeout=8)
        ids = [m.get("id") for m in d.get("data", []) if isinstance(m, dict)]
        return True, {"ms": int((time.time() - t0) * 1000), "models": ids[:40]}
    except urllib.error.HTTPError as e:
        return False, {"msg": "HTTP %s from %s" % (e.code, base)}
    except Exception as e:  # noqa: BLE001
        return False, {"msg": str(e)[:160]}


# ---------------------------------------------------------------- Unsloth (desktop GPU)

LOCAL_KINDS = ("unsloth", "lmstudio", "ollama")


def provider_root(cfg, name):
    base, key = provider_info(cfg, name)
    return (base[:-3] if base.endswith("/v1") else base.rstrip("/")), key


def detect_backend(cfg, name):
    """Work out what kind of server a provider is. Cached per provider for 5 minutes."""
    hint = (CFG.get("backend_hint") or {}).get(name)
    if hint:
        return hint
    det = CACHE.setdefault("kinds", {})
    ent = det.get(name)
    if ent and time.time() - ent["at"] < 300:
        return ent["kind"]
    root, key = provider_root(cfg, name)
    kind = "generic"
    for probe, k in (("/v1/status", "unsloth"), ("/api/v0/models", "lmstudio"), ("/api/tags", "ollama")):
        try:
            http_json(root + probe, key=key, timeout=3)
            kind = k
            break
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and k == "unsloth":
                kind = k  # Unsloth answers auth errors on /v1/status; still Unsloth
                break
        except Exception:  # noqa: BLE001
            continue
    det[name] = {"kind": kind, "at": time.time()}
    return kind


def local_provider(cfg=None):
    """The provider whose server we can inspect for a loaded model (first local kind found)."""
    cfg = cfg or oc_config()
    for name in cfg.get("models", {}).get("providers", {}):
        if detect_backend(cfg, name) in LOCAL_KINDS:
            return name
    return None


def server_status(cfg, name):
    """Status of one provider's server, normalised across backends."""
    kind = detect_backend(cfg, name)
    root, key = provider_root(cfg, name)
    base, _ = provider_info(cfg, name)
    out = {"provider": name, "kind": kind, "baseUrl": base, "ok": False, "active": None, "context": None,
           "models": [], "caps": {"load": False, "estimate": False, "downloaded": False, "loadedContext": False}}
    try:
        if kind == "unsloth":
            st = http_json(root + "/v1/status", key=key, timeout=3)
            models = http_json(root + "/v1/models", key=key, timeout=3).get("data", [])
            out.update({"ok": True, "active": st.get("active_model"), "context": st.get("context_length"),
                        "gpuLayers": "%s/%s" % (st.get("offloaded_layers"), st.get("offload_total_layers")),
                        "models": [{"id": m["id"], "quant": m.get("quant"), "loaded": m.get("loaded"), "task": m.get("task"),
                                    "maxContext": m.get("max_context_length")} for m in models],
                        "caps": {"load": True, "estimate": True, "downloaded": True, "loadedContext": True}})
        elif kind == "lmstudio":
            d = http_json(root + "/api/v0/models", key=key, timeout=3)
            ms = [m for m in d.get("data", d if isinstance(d, list) else []) if isinstance(m, dict)]
            loaded = [m for m in ms if m.get("state") == "loaded" and m.get("type", "llm") in ("llm", "vlm")]
            out.update({"ok": True, "active": loaded[0]["id"] if loaded else None,
                        "context": (loaded[0].get("loaded_context_length") if loaded else None),
                        "models": [{"id": m.get("id"), "quant": m.get("quantization"), "loaded": m.get("state") == "loaded",
                                    "task": None if m.get("type", "llm") in ("llm", "vlm") else m.get("type"),
                                    "maxContext": m.get("max_context_length")} for m in ms],
                        "caps": {"load": False, "estimate": False, "downloaded": True, "loadedContext": True}})
        elif kind == "ollama":
            tags = http_json(root + "/api/tags", key=key, timeout=3).get("models", [])
            ps = http_json(root + "/api/ps", key=key, timeout=3).get("models", [])
            running = {m.get("name") or m.get("model"): m for m in ps}
            first = next(iter(running.values()), None)
            out.update({"ok": True, "active": (first or {}).get("name") or (first or {}).get("model"),
                        "context": (first or {}).get("context_length"),
                        "models": [{"id": m.get("name"), "quant": (m.get("details") or {}).get("quantization_level"),
                                    "loaded": (m.get("name") in running), "task": None, "maxContext": None} for m in tags],
                        "caps": {"load": False, "estimate": False, "downloaded": True, "loadedContext": bool((first or {}).get("context_length"))}})
        else:
            d = http_json(base.rstrip("/") + "/models", key=key, timeout=4)
            out.update({"ok": True, "models": [{"id": m.get("id"), "loaded": None, "task": None, "maxContext": None}
                                               for m in d.get("data", []) if isinstance(m, dict)]})
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:160]
    return out


def unsloth_status():
    """Status of the primary local server (kept under its old name so the guards keep working)."""
    cfg = oc_config()
    name = local_provider(cfg)
    if not name:
        return {"ok": False, "error": "no local model server detected among OpenClaw's providers"}
    st = server_status(cfg, name)
    return st


def unsloth_estimate(model_path, variant, ctx):
    cfg = oc_config()
    name = local_provider(cfg)
    if not name or detect_backend(cfg, name) != "unsloth":
        return {"ok": False, "error": "memory estimates are only available for Unsloth Studio"}
    root, key = provider_root(cfg, name)
    body = {"model_path": model_path, "gguf_variant": variant or None, "max_seq_length": int(ctx or 0)}
    try:
        return {"ok": True, "estimate": http_json(root + "/api/inference/estimate-memory", "POST", body, key, 30)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def unsloth_load(model_path, variant, ctx, why=""):
    cfg = oc_config()
    name = local_provider(cfg)
    if not name or detect_backend(cfg, name) != "unsloth":
        return False, "loading models from here is only supported for Unsloth Studio"
    root, key = provider_root(cfg, name)
    body = {"model_path": model_path, "gguf_variant": variant or None, "max_seq_length": int(ctx or 0)}
    try:
        http_json(root + "/v1/load", "POST", body, key, 30)
        log_event("🖥️ Desktop load requested: %s %s ctx=%s%s" % (model_path, variant or "", ctx or "auto", (" — " + why) if why else ""))
        return True, "load requested"
    except Exception as e:  # noqa: BLE001
        log_event("❌ Desktop load failed: %s — %s" % (model_path, e))
        return False, str(e)


# ---------------------------------------------------------------- agent lifecycle

AGENT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}$")
TOOL_PROFILES = ("minimal", "messaging", "coding", "full")


def run_oc(args, timeout=180):
    r = subprocess.run([OPENCLAW, *args], capture_output=True, text=True, timeout=timeout, cwd=OC_HOME,
                       env={**os.environ, "PATH": ENV_PATH})
    out = "\n".join(l for l in (r.stdout + r.stderr).splitlines() if "session-sqlite" not in l and "reclamation" not in l).strip()
    return r.returncode, out


def create_agent(b):
    aid = str(b.get("id", "")).strip().lower()
    if not AGENT_ID_RE.match(aid):
        return False, "id must be 2-31 chars: lowercase letters, digits, dashes, starting with a letter"
    cfg = oc_config()
    if aid in cfg.get("agents", {}).get("entries", {}):
        return False, "an agent with that id already exists"
    model = str(b.get("model") or "")
    refs = {m["ref"] for m in model_catalog(cfg)}
    if model and model not in refs:
        return False, "unknown model " + model
    ws = os.path.join(OC_HOME, "workspace-" + aid)
    args = ["agents", "add", aid, "--non-interactive", "--workspace", ws] + (["--model", model] if model else [])
    rc, out = run_oc(args)
    if rc != 0:
        log_event("❌ Create agent %s failed: %s" % (aid, out[-160:]))
        return False, out[-300:]
    name = str(b.get("name") or aid).strip()
    emoji = str(b.get("emoji") or "").strip()
    theme = str(b.get("theme") or "").strip()
    ident = ["agents", "set-identity", "--agent", aid, "--name", name] + (["--emoji", emoji] if emoji else []) + (["--theme", theme] if theme else [])
    run_oc(ident)
    entry = {}
    prof = b.get("toolProfile")
    if prof in TOOL_PROFILES:
        entry["tools"] = {"profile": prof}
    if b.get("thinking"):
        entry["thinkingDefault"] = b["thinking"]
    if b.get("promptBudget"):
        entry["bootstrapTotalMaxChars"] = int(b["promptBudget"])
    if b.get("note"):
        entry["description"] = str(b["note"])
    patch = {"agents": {"entries": {aid: entry}}}
    if model:
        patch["agents"]["defaults"] = {"models": {model: {}}}
    if entry or model:
        apply_patch(patch, "Configured new agent %s" % aid)
    if b.get("skipRitual", True):
        try:
            with open(os.path.join(ws, "IDENTITY.md"), "w") as f:
                f.write("# IDENTITY.md\n\n- **Name:** %s\n- **Creature:** %s\n- **Theme:** %s\n- **Emoji:** %s\n" % (name, b.get("creature") or "AI assistant", theme or "helpful", emoji))
            bs = os.path.join(ws, "BOOTSTRAP.md")
            if os.path.exists(bs):
                os.replace(bs, os.path.join(ws, "BOOTSTRAP.md.skipped"))
            soul = os.path.join(ws, "SOUL.md")
            if theme and os.path.exists(soul):
                with open(soul) as f:
                    txt = f.read()
                with open(soul, "w") as f:
                    f.write("# SOUL.md\n\nYou are **%s** %s — %s.\n\n" % (name, emoji, theme) + txt.split("\n", 1)[1] if txt.startswith("#") else txt)
        except OSError as e:
            log_event("⚠️ Agent %s created, but workspace files not customised: %s" % (aid, e))
    log_event("➕ Created agent %s (%s %s) workspace %s" % (aid, emoji, name, ws))
    return True, "created"


def delete_agent(aid, confirm):
    aid = str(aid).strip()
    if aid == "main":
        return False, "the main agent can't be deleted"
    if confirm != aid:
        return False, "type the agent id exactly to confirm"
    cfg = oc_config()
    ent = cfg.get("agents", {}).get("entries", {}).get(aid)
    if not ent:
        return False, "no such agent"
    ws = ent.get("workspace") or os.path.join(OC_HOME, "workspace-" + aid)
    adir = ent.get("agentDir") or os.path.join(OC_HOME, "agents", aid)
    bdir = os.path.join(OC_HOME, "backups")
    os.makedirs(bdir, exist_ok=True)
    zpath = os.path.join(bdir, "agent-%s-%s.zip" % (aid, datetime.now().strftime("%Y%m%d-%H%M%S")))
    items = [os.path.relpath(x, OC_HOME) for x in (ws, adir) if os.path.isdir(x) and x.startswith(OC_HOME)]
    if items:
        z = subprocess.run([shutil.which("zip") or "zip", "-qr", zpath, *items], cwd=OC_HOME, capture_output=True, text=True, timeout=300)
        if z.returncode != 0:
            return False, "backup failed, nothing deleted: " + (z.stderr or z.stdout).strip()[-160:]
    rc, out = run_oc(["agents", "delete", aid, "--force"])
    if rc != 0:
        log_event("❌ Delete agent %s failed: %s" % (aid, out[-160:]))
        return False, out[-300:]
    # prune anything still pointing at the agent
    cfg = oc_config()
    binds = [x for x in cfg.get("bindings", []) if x.get("agentId") != aid]
    if len(binds) != len(cfg.get("bindings", [])):
        apply_patch({"bindings": binds}, "Removed routing rules for deleted agent %s" % aid, ("--replace-path", "bindings"))
    allow = (cfg.get("tools", {}).get("agentToAgent", {}) or {}).get("allow") or []
    if aid in allow:
        apply_patch({"tools": {"agentToAgent": {"allow": [a for a in allow if a != aid]}}}, "Removed %s from agent-to-agent allow list" % aid, ("--replace-path", "tools.agentToAgent.allow"))
    SESS["at"] = 0
    log_event("🗑️ Deleted agent %s — backup at %s" % (aid, zpath if items else "(nothing to back up)"))
    return True, zpath if items else "deleted"


def update_identity(aid, name, emoji, theme):
    if aid not in oc_config().get("agents", {}).get("entries", {}):
        return False, "no such agent"
    args = ["agents", "set-identity", "--agent", aid]
    if name:
        args += ["--name", str(name)]
    if emoji:
        args += ["--emoji", str(emoji)]
    if theme is not None:
        args += ["--theme", str(theme)]
    rc, out = run_oc(args)
    log_event(("🪪 %s identity → %s %s" % (aid, emoji or "", name or "")) if rc == 0 else ("❌ identity update for %s failed: %s" % (aid, out[-120:])))
    return rc == 0, out[-200:]


def update_tools(aid, profile):
    if aid not in oc_config().get("agents", {}).get("entries", {}):
        return False, "no such agent"
    if profile and profile not in TOOL_PROFILES:
        return False, "unknown tool profile"
    return apply_patch({"agents": {"entries": {aid: {"tools": {"profile": profile or None}}}}}, "%s tool access → %s" % (aid, profile or "(inherit)"))


# ---------------------------------------------------------------- sessions (conversation size per agent)

SESS = {"at": 0, "data": None}


def gateway_call(method, params, timeout=20):
    r = subprocess.run([OPENCLAW, "gateway", "call", method, "--params", json.dumps(params), "--json"],
                       capture_output=True, text=True, timeout=timeout, cwd=OC_HOME,
                       env={**os.environ, "PATH": ENV_PATH})
    raw = r.stdout
    i = raw.find("{")
    if i < 0:
        raise RuntimeError((r.stderr or raw).strip()[-200:] or "no output")
    return json.loads(raw[i:])


def sessions_view(fresh=False):
    if not fresh and SESS["data"] and time.time() - SESS["at"] < 30:
        return SESS["data"]
    cfg = oc_config()
    out = []
    for aid in cfg.get("agents", {}).get("entries", {}):
        key = "agent:%s:main" % aid
        try:
            d = gateway_call("sessions.describe", {"key": key})
            sess = d.get("session", d)
            b = sess.get("contextBudgetStatus") or {}
            used = b.get("estimatedPromptTokens")
            if used is None and sess.get("totalTokens"):
                used = int(sess["totalTokens"])  # last turn's prompt+reply ≈ conversation size
            elif used is None and (sess.get("inputTokens") or 0) > 0:
                used = int(sess.get("inputTokens") or 0) + int(sess.get("outputTokens") or 0)
            budget = b.get("contextTokenBudget") or sess.get("contextTokens")
            pct = round(100.0 * used / budget) if used and budget else None
            state = "unknown" if pct is None else ("over" if (b.get("overflowTokens") or 0) > 0 or pct >= 100 else "near" if pct >= 80 else "ok")
            out.append({"agent": aid, "key": key, "model": sess.get("model"), "provider": sess.get("modelProvider"),
                        "budget": budget, "used": used, "pct": pct, "state": state, "route": b.get("route"),
                        "messages": b.get("messageCount"), "updatedAt": sess.get("updatedAt"), "overflow": b.get("overflowTokens") or 0})
        except Exception as e:  # noqa: BLE001
            out.append({"agent": aid, "key": key, "error": str(e)[:160], "state": "unknown"})
    SESS.update({"at": time.time(), "data": out})
    return out


def gateway_restart():
    """Restart the gateway: a custom command if configured, else the openclaw CLI, else the macOS LaunchAgent directly."""
    custom = CFG.get("gateway_restart_cmd")
    if custom:
        r = subprocess.run(custom, shell=True, capture_output=True, text=True, timeout=120, env={**os.environ, "PATH": ENV_PATH})
        rc, out = r.returncode, (r.stdout + r.stderr).strip()
    else:
        rc, out = run_oc(["gateway", "restart"], timeout=120)
        if rc != 0 and sys.platform == "darwin":
            label = CFG.get("gateway_launchd_label", "ai.openclaw.gateway")
            r = subprocess.run(["launchctl", "kickstart", "-k", "gui/%d/%s" % (os.getuid(), label)], capture_output=True, text=True, timeout=60)
            rc, out = r.returncode, (r.stdout + r.stderr).strip() or out
    if rc != 0:
        log_event("❌ Gateway restart failed: %s" % out[-160:])
        return False, out[-300:]
    up = False
    for _ in range(30):
        time.sleep(1)
        if port_open("127.0.0.1", 18789):
            up = True
            break
    log_event("♻️ Gateway restarted" + ("" if up else " — but it isn't listening on 18789 yet"))
    SESS["at"] = 0
    return up, "gateway restarted" if up else "restart issued, but the gateway hasn't come back on 18789 yet — check openclaw gateway status"


def session_reset(agent):
    r = subprocess.run([OPENCLAW, "agent", "--agent", agent, "--message", "/new"], capture_output=True, text=True,
                       timeout=120, cwd=OC_HOME, env={**os.environ, "PATH": ENV_PATH})
    ok = "New session started" in (r.stdout + r.stderr)
    log_event(("🧹 Reset %s's conversation (/new)" % agent) if ok else ("❌ Reset of %s failed: %s" % (agent, (r.stdout + r.stderr).strip()[-120:])))
    SESS["at"] = 0
    return ok, "conversation reset" if ok else (r.stdout + r.stderr).strip()[-200:]


def session_compact(agent):
    r = subprocess.run([OPENCLAW, "sessions", "compact", "--agent", agent, "agent:%s:main" % agent, "--timeout", "600000"],
                       capture_output=True, text=True, timeout=660, cwd=OC_HOME, env={**os.environ, "PATH": ENV_PATH})
    out = (r.stdout + r.stderr).strip()
    ok = r.returncode == 0 and "error" not in out.lower()
    log_event(("🗜️ Compacted %s's conversation" % agent) if ok else ("❌ Compact of %s failed: %s" % (agent, out[-120:])))
    SESS["at"] = 0
    return ok, out[-300:]


# ---------------------------------------------------------------- health + speed

CACHE = {"unsloth": None, "health": None, "at": 0}


def ping_host(host):
    try:
        return subprocess.run([shutil.which("ping") or "ping", "-c", "1", "-W", "1500", host], capture_output=True, timeout=4).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def poll_once():
    us = unsloth_status()
    h = health(us)
    cfg0 = oc_config()
    CACHE["servers"] = [server_status(cfg0, n) if n != us.get("provider") else us for n in cfg0.get("models", {}).get("providers", {})]
    if us.get("ok"):
        with LOCK:
            st = load_state()
            st["lastDesktop"] = {"active": us.get("active"), "context": us.get("context"),
                                 "seen": datetime.now().strftime("%Y-%m-%d %H:%M")}
            write_json(STATE_FILE, st)
        sync_loaded_context(us)
    else:
        url = h.get("unsloth", {}).get("url") or ""
        host = url.split("//")[-1].split("/")[0].split(":")[0]
        port = int(url.split("//")[-1].split("/")[0].split(":")[1]) if ":" in url.split("//")[-1].split("/")[0] else (443 if url.startswith("https") else 80)
        h["unsloth"]["hostUp"] = ping_host(host) if host else None
        h["unsloth"]["portOpen"] = port_open(host, port) if host else None
        h["unsloth"]["lastSeen"] = load_state().get("lastDesktop")
    CACHE.update({"unsloth": us, "health": h, "at": time.time()})


def sync_loaded_context(us):
    """Keep the loaded desktop model's OpenClaw entry in step with the context Unsloth actually loaded."""
    st = load_state()
    if not st.get("syncContext", True):
        return
    active, loaded = us.get("active"), int(us.get("context") or 0)
    if not active or not loaded:
        return
    cfg = oc_config()
    name, models = local_models(cfg)
    if not name:
        return
    changed = []
    for i, ent in enumerate(models):
        if ent.get("id") in (active, "current") and ent.get("contextWindow") != loaded:
            changed.append("%s %s→%s" % (ent["id"], ent.get("contextWindow"), loaded))
            models[i] = {**ent, "contextWindow": loaded}
    if changed:
        apply_patch({"models": {"providers": {name: {"models": models}}}},
                    "🔄 Auto-synced context to %s (desktop loaded %s): %s" % (loaded, active, "; ".join(changed)))


def sync_context_now():
    """One-shot: set every desktop model entry that agents use (plus `current` and the loaded model) to the context Unsloth loaded."""
    us = cached("unsloth")
    if not us.get("ok"):
        return False, {"msg": "desktop is offline — nothing to sync from"}
    loaded, active = int(us.get("context") or 0), us.get("active") or ""
    if not loaded:
        return False, {"msg": "Unsloth didn't report a loaded context"}
    cfg = oc_config()
    name, models = local_models(cfg)
    if not name:
        return False, {"msg": "no local model server detected"}
    av = agents_view(cfg)
    refs = {av["default"]["model"]} | {a["effective"] for a in av["agents"]}
    targets = {r.split("/", 1)[1] for r in refs if r and r.startswith(name + "/")} | {"current", active}
    changed, skipped, same = [], [], []
    for i, m in enumerate(models):
        if m.get("id") not in targets:
            continue
        if re.search(r"-\d+k$", m["id"]):
            skipped.append(m["id"])  # deliberate smaller copies stay as they are
            continue
        if m.get("contextWindow") != loaded:
            changed.append("%s %s→%s" % (m["id"], m.get("contextWindow"), loaded))
            models[i] = {**m, "contextWindow": loaded}
        else:
            same.append(m["id"])
    if changed:
        ok, msg = apply_patch({"models": {"providers": {name: {"models": models}}}},
                              "🔄 Synced context to %s (loaded %s): %s" % (loaded, active, "; ".join(changed)))
        if not ok:
            return False, {"msg": msg}
    return True, {"loaded": loaded, "active": active, "changed": changed, "unchanged": same, "skippedCopies": skipped}


def poller_loop():
    while True:
        try:
            poll_once()
        except Exception as e:  # noqa: BLE001
            log_event("❌ poller error: %s" % e)
        time.sleep(15)


def cached(kind):
    if CACHE["at"] == 0:
        try:
            poll_once()
        except Exception:  # noqa: BLE001
            pass
    return CACHE.get(kind) or {"ok": False, "error": "not polled yet"}

def port_open(host, port):
    import socket
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def health(us=None):
    cfg = oc_config()
    name = lp(cfg)
    root = provider_root(cfg, name)[0] if name else ""
    us = us or unsloth_status()
    others = []
    for pname in cfg.get("models", {}).get("providers", {}):
        if pname == name:
            continue
        base, key = provider_info(cfg, pname)
        ok = False
        try:
            http_json(base.rstrip("/") + "/models", key=key, timeout=4)
            ok = True
        except Exception:  # noqa: BLE001
            pass
        others.append({"id": pname, "ok": ok, "url": base, "kind": detect_backend(cfg, pname)})
    return {"gateway": port_open("127.0.0.1", 18789),
            "unsloth": {"ok": us.get("ok"), "active": us.get("active"), "error": us.get("error"), "url": root,
                        "provider": name, "kind": us.get("kind")},
            "others": others, "mac": next((o for o in others if o["id"] == "mac"), {"ok": None, "url": ""})}


def speed_test(ref):
    cfg = oc_config()
    m = next((x for x in model_catalog(cfg) if x["ref"] == ref), None)
    if not m:
        return {"ok": False, "error": "unknown model"}
    _, key = provider_info(cfg, m["provider"])
    body = {"model": m["id"], "stream": True, "max_tokens": 64,
            "messages": [{"role": "user", "content": "Count from 1 to 20 separated by spaces."}]}
    req = urllib.request.Request(m["baseUrl"].rstrip("/") + "/chat/completions", data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", "Bearer " + key)
    t0 = time.time()
    first = None
    chunks = 0
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            for line in r:
                line = line.decode(errors="ignore").strip()
                if not line.startswith("data:") or line.endswith("[DONE]"):
                    continue
                d = json.loads(line[5:])
                for c in d.get("choices", []):
                    dl = c.get("delta", {})
                    if dl.get("content") or dl.get("reasoning_content"):
                        if first is None:
                            first = time.time()
                        chunks += 1
        t1 = time.time()
        if first is None:
            return {"ok": False, "error": "no tokens returned"}
        gen = t1 - first
        res = {"ok": True, "ttft": round(first - t0, 2), "tps": round(chunks / gen, 1) if gen > 0 else None, "chunks": chunks}
        log_event("⏱️ %s: first token %.2fs, ~%s tok/s" % (ref, res["ttft"], res["tps"]))
        return res
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------- schedules

def run_schedule(rule, reason):
    acts = rule.get("actions", {})
    results = []
    u = acts.get("unsloth")
    if u and u.get("model_path"):
        ok, msg = unsloth_load(u["model_path"], u.get("gguf_variant"), u.get("max_seq_length"), "schedule: " + rule.get("name", ""))
        results.append(msg)
    for agent, model in (acts.get("agents") or {}).items():
        if model:
            ok, msg = set_agent_model(agent, model if model != "__inherit__" else "", None, None)
            results.append("%s: %s" % (agent, "ok" if ok else msg))
    log_event("🗓️ Schedule '%s' ran (%s)" % (rule.get("name", "?"), reason))
    return results


def scheduler_loop():
    while True:
        try:
            now = datetime.now()
            hm, today, dow = now.strftime("%H:%M"), now.strftime("%Y-%m-%d"), now.weekday()
            st = load_state()
            for rule in st["schedules"]:
                if not rule.get("enabled"):
                    continue
                if rule.get("time") == hm and dow in rule.get("days", list(range(7))):
                    key = rule["id"] + "@" + today
                    if st["lastRun"].get(rule["id"]) != today:
                        with LOCK:
                            st2 = load_state()
                            st2["lastRun"][rule["id"]] = today
                            write_json(STATE_FILE, st2)
                        run_schedule(rule, "at " + hm)
        except Exception as e:  # noqa: BLE001
            log_event("❌ scheduler error: %s" % e)
        time.sleep(20)


# ---------------------------------------------------------------- auth

def load_sessions():
    now = time.time()
    return {k: v for k, v in read_json(SESSIONS_FILE, {}).items() if v > now}


def save_session(tok, exp):
    with LOCK:
        d = load_sessions()
        d[tok] = exp
        write_json(SESSIONS_FILE, d)


def drop_session(tok):
    with LOCK:
        d = load_sessions()
        d.pop(tok, None)
        write_json(SESSIONS_FILE, d)


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 300000).hex()
    return {"salt": salt, "hash": h}


def check_pw(pw):
    a = read_json(AUTH_FILE, None)
    if not a:
        return False
    return hmac.compare_digest(hash_pw(pw, a["salt"])["hash"], a["hash"])


def ip_allowed(ip):
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in n for n in ALLOWED_NETS)
    except ValueError:
        return False


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "ModelControl/1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if "text" in ctype or "json" in ctype else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _gate(self):
        if not ip_allowed(self.client_address[0]):
            self._send(403, {"error": "LAN/Tailscale only"})
            return False
        if any(h in self.headers for h in PROXY_HEADERS):
            self._send(403, {"error": "proxied requests are not allowed"})
            return False
        return True

    def _session(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        tok = c.get("mc_session")
        if not tok:
            return False
        return tok.value in load_sessions()

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n > 100000:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def do_GET(self):
        if not self._gate():
            return
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html")
        if path == "/api/me":
            return self._send(200, {"authed": self._session(), "hasPassword": os.path.exists(AUTH_FILE)})
        if not self._session():
            return self._send(401, {"error": "login required"})
        cfg = oc_config()
        if path == "/api/state":
            st = load_state()
            us = cached("unsloth")
            desk = [m for m in (us.get("models") or []) if not m.get("task")] if us.get("ok") else []
            provs = {k: {"baseUrl": v.get("baseUrl", ""), "api": v.get("api", ""), "hasKey": bool(v.get("apiKey")) and v.get("apiKey") != "local",
                         "count": len(v.get("models", []))} for k, v in cfg.get("models", {}).get("providers", {}).items()}
            usage = {m["ref"]: _users_of(cfg, m["ref"]) for m in model_catalog(cfg)}
            servers = CACHE.get("servers") or []
            return self._send(200, {"agents": agents_view(cfg), "models": model_catalog(cfg), "providers": provs, "usage": usage,
                                    "servers": servers, "localProvider": lp(cfg),
                                    "desktopModels": desk, "desktopDown": not us.get("ok"), "unsloth": us,
                                    "health": cached("health"), "polledAt": CACHE["at"],
                                    "schedules": st["schedules"], "lastRun": st["lastRun"], "log": st["log"][:100],
                                    "syncContext": st.get("syncContext", True), "sessions": SESS["data"]})
        if path == "/api/sessions":
            return self._send(200, {"sessions": sessions_view("fresh" in self.path), "at": SESS["at"]})
        if path == "/api/unsloth":
            if "fresh" in self.path:
                poll_once()
            return self._send(200, cached("unsloth"))
        if path == "/api/health":
            if "fresh" in self.path:
                poll_once()
            return self._send(200, cached("health"))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._gate():
            return
        path = self.path.split("?")[0]
        # CSRF: require our custom header, and if an Origin is sent it must match the Host.
        origin = self.headers.get("Origin")
        if self.headers.get("X-Model-UI") != "1" or (origin and origin.split("//", 1)[-1] != self.headers.get("Host")):
            return self._send(403, {"error": "bad request origin"})
        b = self._body()
        ip = self.client_address[0]
        if path == "/api/login":
            now = time.time()
            with LOCK:
                fails = [t for t in FAILED_LOGINS.get(ip, []) if now - t < 300]
                FAILED_LOGINS[ip] = fails
            if len(fails) >= 5:
                return self._send(429, {"error": "too many attempts, wait 5 minutes"})
            if check_pw(str(b.get("password", ""))):
                tok = secrets.token_urlsafe(32)
                save_session(tok, now + SESSION_TTL)
                return self._send(200, {"ok": True}, extra={"Set-Cookie": "mc_session=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d" % (tok, SESSION_TTL)})
            with LOCK:
                FAILED_LOGINS.setdefault(ip, []).append(now)
            time.sleep(1)
            return self._send(401, {"error": "wrong password"})
        if not self._session():
            return self._send(401, {"error": "login required"})
        if path == "/api/logout":
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            if c.get("mc_session"):
                drop_session(c["mc_session"].value)
            return self._send(200, {"ok": True}, extra={"Set-Cookie": "mc_session=; Max-Age=0; Path=/"})
        if path == "/api/agent":
            ok, msg = set_agent_model(b.get("agent", ""), b.get("model") or "", [f for f in b.get("fallbacks", []) if f], b.get("note"),
                                      b.get("thinking"), b.get("promptBudget"))
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/catalog/add":
            ok, msg = add_desktop_model(str(b.get("id", "")))
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/agent/create":
            ok, msg = create_agent(b)
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/agent/delete":
            ok, msg = delete_agent(b.get("agent", ""), str(b.get("confirm", "")))
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/agent/identity":
            ok, msg = update_identity(str(b.get("agent", "")), b.get("name"), b.get("emoji"), b.get("theme"))
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/agent/tools":
            ok, msg = update_tools(str(b.get("agent", "")), b.get("profile") or "")
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/gateway/restart":
            ok, msg = gateway_restart()
            return self._send(200 if ok else 500, {"ok": ok, "msg": msg})
        if path == "/api/session/reset":
            ok, msg = session_reset(str(b.get("agent", "")))
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/session/compact":
            ok, msg = session_compact(str(b.get("agent", "")))
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/models/add":
            ok, msg = model_add(b); return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/models/update":
            ok, msg = model_update(b); return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/models/delete":
            ok, msg = model_delete(str(b.get("ref", ""))); return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/providers/add":
            ok, msg = provider_add(b); return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/providers/delete":
            ok, msg = provider_delete(str(b.get("id", ""))); return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/providers/test":
            ok, info = provider_test(str(b.get("id", ""))); return self._send(200 if ok else 400, {"ok": ok, **info})
        if path == "/api/sync-context":
            ok, info = sync_context_now()
            return self._send(200 if ok else 400, {"ok": ok, **info})
        if path == "/api/settings":
            with LOCK:
                st = load_state()
                if "syncContext" in b:
                    st["syncContext"] = bool(b["syncContext"])
                write_json(STATE_FILE, st)
            log_event("⚙️ Auto-sync desktop context: %s" % ("on" if st.get("syncContext", True) else "off"))
            return self._send(200, {"ok": True, "syncContext": st.get("syncContext", True)})
        if path == "/api/alias":
            ok, msg = add_alias(b.get("ref", ""), b.get("contextWindow") or 0, b.get("maxTokens"))
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/model":
            ok, msg = set_model_limits(b.get("ref", ""), b.get("contextWindow"), b.get("maxTokens"))
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/unsloth/estimate":
            return self._send(200, unsloth_estimate(b.get("model_path"), b.get("gguf_variant"), b.get("max_seq_length")))
        if path == "/api/unsloth/load":
            if not b.get("confirmed"):
                return self._send(400, {"ok": False, "msg": "confirmation required"})
            ok, msg = unsloth_load(b.get("model_path"), b.get("gguf_variant"), b.get("max_seq_length"), b.get("why", ""))
            return self._send(200 if ok else 400, {"ok": ok, "msg": msg})
        if path == "/api/test":
            return self._send(200, speed_test(b.get("ref", "")))
        if path == "/api/schedules":
            rules = b.get("schedules", [])
            for r in rules:
                r.setdefault("id", secrets.token_hex(4))
            with LOCK:
                st = load_state()
                st["schedules"] = rules
                write_json(STATE_FILE, st)
            log_event("🗓️ Schedules saved (%d rules)" % len(rules))
            return self._send(200, {"ok": True, "schedules": rules})
        if path == "/api/schedules/run":
            rule = next((r for r in load_state()["schedules"] if r.get("id") == b.get("id")), None)
            if not rule:
                return self._send(404, {"ok": False, "msg": "no such rule"})
            return self._send(200, {"ok": True, "results": run_schedule(rule, "run now")})
        return self._send(404, {"error": "not found"})


def main():
    if "--set-password" in sys.argv:
        pw = getpass.getpass("New Model Control password: ")
        if len(pw) < 8 or pw != getpass.getpass("Again: "):
            sys.exit("Passwords must match and be at least 8 characters.")
        write_json(AUTH_FILE, hash_pw(pw))
        print("Password saved.")
        return
    if "--mint-session" in sys.argv:  # short-lived session for local testing (prints the cookie value)
        tok = secrets.token_urlsafe(32)
        save_session(tok, time.time() + 600)
        print(tok)
        return
    if not os.path.exists(AUTH_FILE):
        sys.exit("No password set. Run: %s --set-password" % sys.argv[0])
    threading.Thread(target=scheduler_loop, daemon=True).start()
    threading.Thread(target=poller_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("Model Control on http://0.0.0.0:%d  (openclaw=%s, home=%s)" % (PORT, OPENCLAW, OC_HOME), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
