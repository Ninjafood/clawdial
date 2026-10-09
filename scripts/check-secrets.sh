#!/usr/bin/env bash
# Refuses to let obviously private things into the repo: keys, phone numbers, concrete private IPs, tailnet/tunnel hostnames.
# CIDR ranges like 192.168.0.0/16 are config defaults and are ignored. Add your own regexes to .secret-patterns, one per line.
set -euo pipefail
cd "$(dirname "$0")/.."
patterns='sk-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b[0-9]{3}[-. ][0-9]{3}[-. ][0-9]{4}\b|\b\+?1[0-9]{10}\b|\b(100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])|192\.168|172\.(1[6-9]|2[0-9]|3[01])|10)\.[0-9]+\.[0-9]+\b(?!/)|\.ts\.net|cloudflareaccess|trycloudflare|@gmail\.com'
[ -f .secret-patterns ] && patterns="$patterns|$(paste -sd'|' .secret-patterns)"
hits=$(git ls-files -co --exclude-standard | grep -vE '^(scripts/check-secrets\.sh|\.secret-patterns)$' | xargs grep -nIP "$patterns" 2>/dev/null | grep -vE 'example-cloud|0\.0\.0\.0|127\.0\.0\.1|192\.168\.0\.50' || true)
if [ -n "$hits" ]; then echo "Possible secrets / private details found:"; echo "$hits"; exit 1; fi
echo "clean"
