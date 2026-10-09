#!/usr/bin/env bash
# Installs Model Control as a per-user LaunchAgent on macOS (starts at login, restarts if it dies).
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
LABEL=ai.clawdial.model-control
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PY="$(command -v python3)"
[ -f "$DIR/auth.json" ] || "$PY" -I "$DIR/server.py" --set-password
mkdir -p "$HOME/Library/Logs/clawdial"
cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$PY</string><string>-I</string><string>$DIR/server.py</string></array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string></dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/clawdial/model-control.log</string>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/clawdial/model-control.log</string>
</dict></plist>
PL
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "Running. Open http://localhost:$(python3 -c "import json;print(json.load(open('$DIR/config.json')).get('port',8790) if __import__('os').path.exists('$DIR/config.json') else 8790)")/"
