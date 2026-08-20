#!/bin/sh
# Install observability-agent on Amazon Linux 2023 or Ubuntu.
# Usage: ./install.sh /path/to/observability-agent [native-intake-url]
set -eu

BINARY=${1:-}
ENDPOINT=${2:-}
PREFIX=${PREFIX:-/usr}
SYSCONF=${SYSCONF:-/etc/observability-agent}

if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
  echo "usage: $0 /path/to/observability-agent [https://intake.example.com]" >&2
  exit 1
fi

install -d -m 0755 "$PREFIX/bin"
install -d -m 0755 "$SYSCONF"
install -m 0755 "$BINARY" "$PREFIX/bin/observability-agent"

if [ ! -f "$SYSCONF/agent.json" ]; then
  if [ -f "$(dirname "$0")/../agent.example.json" ]; then
    install -m 0644 "$(dirname "$0")/../agent.example.json" "$SYSCONF/agent.json"
  else
    echo '{"schema_version":1,"modules":{"host":{"enabled":true},"process":{"enabled":true},"logs":{"enabled":true},"otel-engine":{"enabled":true},"discovery":{"enabled":true}}}' > "$SYSCONF/agent.json"
    chmod 0644 "$SYSCONF/agent.json"
  fi
fi

if [ -n "$ENDPOINT" ]; then
  printf 'OBSAGENT_EXPORT_ENDPOINT=%s\n' "$ENDPOINT" > "$SYSCONF/agent.env"
  chmod 0600 "$SYSCONF/agent.env"
fi

UNIT_SRC="$(dirname "$0")/observability-agent.service"
if [ -f "$UNIT_SRC" ]; then
  install -m 0644 "$UNIT_SRC" /etc/systemd/system/observability-agent.service
  systemctl daemon-reload
  systemctl enable --now observability-agent.service
fi

echo "installed $PREFIX/bin/observability-agent"
"$PREFIX/bin/observability-agent" --check --config "$SYSCONF/agent.json" || true
