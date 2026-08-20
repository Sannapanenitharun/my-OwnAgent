#!/bin/sh
# Auto-detect Linux or macOS, download the matching agent, install as a service.
#
#   curl -fsSL https://raw.githubusercontent.com/Sannapanenitharun/my-OwnAgent/main/packaging/get.sh \
#     | sudo sh -s -- https://INTAKE_HOST:8080
#
# Windows (PowerShell as Administrator):
#   irm https://raw.githubusercontent.com/Sannapanenitharun/my-OwnAgent/main/packaging/get.ps1 | iex
#   (pass -Endpoint https://INTAKE_HOST:8080)
#
# Optional env:
#   OBSAGENT_VERSION=v0.4.0
#   OBSAGENT_REPO=owner/name
set -eu

ENDPOINT=${1:-}
REPO=${OBSAGENT_REPO:-Sannapanenitharun/my-OwnAgent}
VERSION=${OBSAGENT_VERSION:-latest}

if [ -z "$ENDPOINT" ]; then
  echo "usage: curl -fsSL .../packaging/get.sh | sudo sh -s -- https://intake.example.com:8080" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (sudo)" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux*)  OS=linux ;;
  Darwin*) OS=darwin ;;
  *)
    echo "unsupported OS: $(uname -s) — on Windows use packaging/get.ps1" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *)
    echo "unsupported arch: $(uname -m)" >&2
    exit 1
    ;;
esac

ASSET="observability-agent-${OS}-${ARCH}"
echo "detected ${OS}/${ARCH}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ "$VERSION" = "latest" ]; then
  API="https://api.github.com/repos/${REPO}/releases/latest"
else
  API="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi

echo "resolving release from ${API}"
ASSET_URL=$(curl -fsSL "$API" | sed -n 's/.*"browser_download_url": *"\([^"]*'"${ASSET}"'[^"]*\)".*/\1/p' | head -n 1)
if [ -z "$ASSET_URL" ]; then
  echo "could not find ${ASSET} in release assets for ${VERSION}" >&2
  exit 1
fi

BIN="$TMP/observability-agent"
echo "downloading $ASSET_URL"
curl -fsSL "$ASSET_URL" -o "$BIN"
chmod 0755 "$BIN"

RAW="https://raw.githubusercontent.com/${REPO}/main"
curl -fsSL "$RAW/agent.example.json" -o "$TMP/agent.example.json" || true

write_config() {
  confdir=$1
  bindir=$2
  mkdir -p "$confdir" "$bindir"
  install -m 0755 "$BIN" "$bindir/observability-agent"
  if [ ! -f "$confdir/agent.json" ]; then
    if [ -f "$TMP/agent.example.json" ]; then
      install -m 0644 "$TMP/agent.example.json" "$confdir/agent.json"
    else
      printf '%s\n' '{"schema_version":1,"modules":{"host":{"enabled":true},"process":{"enabled":true},"logs":{"enabled":true},"otel-engine":{"enabled":true},"discovery":{"enabled":true},"container":{"enabled":true},"statsd":{"enabled":true,"settings":{"listen":""}},"httpcheck":{"enabled":true,"settings":{"targets":"ui=http://127.0.0.1:8181/,intake=http://127.0.0.1:8090/healthz"}}}}' > "$confdir/agent.json"
      chmod 0644 "$confdir/agent.json"
    fi
  fi
  # Bake intake into JSON so the agent works even without an env file.
  if command -v python3 >/dev/null 2>&1; then
    ENDPOINT="$ENDPOINT" python3 - "$confdir/agent.json" <<'PY'
import json, os, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    cfg = json.load(f)
cfg.setdefault("export", {}).setdefault("native", {})["endpoint"] = os.environ["ENDPOINT"]
with open(path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
  else
    printf 'OBSAGENT_EXPORT_ENDPOINT=%s\n' "$ENDPOINT" > "$confdir/agent.env"
    chmod 0600 "$confdir/agent.env"
  fi
}

install_linux() {
  write_config /etc/observability-agent /usr/bin
  printf 'OBSAGENT_EXPORT_ENDPOINT=%s\n' "$ENDPOINT" > /etc/observability-agent/agent.env
  chmod 0600 /etc/observability-agent/agent.env
  curl -fsSL "$RAW/packaging/observability-agent.service" -o /etc/systemd/system/observability-agent.service
  systemctl daemon-reload
  systemctl enable --now observability-agent.service
  echo "installed /usr/bin/observability-agent → $ENDPOINT (systemd)"
  /usr/bin/observability-agent --check --config /etc/observability-agent/agent.json || true
}

install_darwin() {
  write_config /usr/local/etc/observability-agent /usr/local/bin
  PLIST=/Library/LaunchDaemons/com.obsagent.observability-agent.plist
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.obsagent.observability-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/observability-agent</string>
    <string>--config</string>
    <string>/usr/local/etc/observability-agent/agent.json</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>OBSAGENT_EXPORT_ENDPOINT</key>
    <string>${ENDPOINT}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/observability-agent.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/observability-agent.err.log</string>
</dict>
</plist>
EOF
  chmod 0644 "$PLIST"
  launchctl bootout system/com.obsagent.observability-agent 2>/dev/null || true
  launchctl bootstrap system "$PLIST"
  launchctl enable system/com.obsagent.observability-agent
  launchctl kickstart -k system/com.obsagent.observability-agent
  echo "installed /usr/local/bin/observability-agent → $ENDPOINT (launchd)"
  /usr/local/bin/observability-agent --check --config /usr/local/etc/observability-agent/agent.json || true
}

case "$OS" in
  linux)  install_linux ;;
  darwin) install_darwin ;;
esac
