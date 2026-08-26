#!/bin/sh
# Auto-detect Linux or macOS, download the matching agent, install as a service.
#
#   curl -fsSL https://github.com/Sannapanenitharun/my-OwnAgent/releases/latest/download/get.sh | sudo bash
#
# Optionally point it at a native intake in the same step:
#   curl -fsSL .../releases/latest/download/get.sh | sudo bash -s -- http://intake.example.com:8090
#
# Windows (PowerShell as Administrator):
#   irm https://github.com/Sannapanenitharun/my-OwnAgent/releases/latest/download/get.ps1 | iex
#
# Every asset is fetched from the release itself, never from a branch and never
# through api.github.com. That keeps the script and the binary it installs from
# ever drifting apart, and avoids the unauthenticated API rate limit (60/hour
# per IP) that makes API-based installers fail behind shared NAT.
#
# Optional env:
#   OBSAGENT_VERSION=v0.4.2          pin a release (default: latest)
#   OBSAGENT_REPO=owner/name
#   OBSAGENT_EXPORT_ENDPOINT=URL     same as the positional argument
set -eu

ENDPOINT=${1:-${OBSAGENT_EXPORT_ENDPOINT:-}}
REPO=${OBSAGENT_REPO:-Sannapanenitharun/my-OwnAgent}
VERSION=${OBSAGENT_VERSION:-latest}

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (sudo)" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux*)  OS=linux ;;
  Darwin*) OS=darwin ;;
  *)
    echo "unsupported OS: $(uname -s) — on Windows use get.ps1" >&2
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

if [ "$VERSION" = "latest" ]; then
  DL="https://github.com/${REPO}/releases/latest/download"
else
  DL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

ASSET="observability-agent-${OS}-${ARCH}"
echo "detected ${OS}/${ARCH}, installing ${VERSION} from ${DL}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BIN="$TMP/observability-agent"
curl -fsSL "$DL/$ASSET" -o "$BIN" || {
  echo "could not download $DL/$ASSET" >&2
  exit 1
}
chmod 0755 "$BIN"

# Config and unit file come from the same release, so they always match the
# binary. Falls back to a minimal inline config if the asset is absent.
curl -fsSL "$DL/agent.example.json" -o "$TMP/agent.example.json" || true

write_config() {
  confdir=$1
  bindir=$2
  mkdir -p "$confdir" "$bindir"
  install -m 0755 "$BIN" "$bindir/observability-agent"
  if [ ! -f "$confdir/agent.json" ]; then
    if [ -s "$TMP/agent.example.json" ]; then
      install -m 0644 "$TMP/agent.example.json" "$confdir/agent.json"
    else
      printf '%s\n' '{"schema_version":1,"modules":{"host":{"enabled":true},"process":{"enabled":true},"logs":{"enabled":true},"otel-engine":{"enabled":true},"discovery":{"enabled":true},"container":{"enabled":true},"statsd":{"enabled":true,"settings":{"listen":""}}}}' > "$confdir/agent.json"
      chmod 0644 "$confdir/agent.json"
    fi
  fi
}

# The endpoint travels as OBSAGENT_EXPORT_ENDPOINT rather than being rewritten
# into the JSON: the config loader treats it as an override, so no JSON parser
# (and no python3) is needed on the target host.
report() {
  if [ -n "$ENDPOINT" ]; then
    echo "installed $1 → exporting to $ENDPOINT"
  else
    echo "installed $1 → collecting locally; dashboard on http://127.0.0.1:8181/"
    echo "to ship data later, set OBSAGENT_EXPORT_ENDPOINT and restart the service"
  fi
}

install_linux() {
  write_config /etc/observability-agent /usr/bin
  if [ -n "$ENDPOINT" ]; then
    printf 'OBSAGENT_EXPORT_ENDPOINT=%s\n' "$ENDPOINT" > /etc/observability-agent/agent.env
    chmod 0600 /etc/observability-agent/agent.env
  fi
  if ! curl -fsSL "$DL/observability-agent.service" -o /etc/systemd/system/observability-agent.service; then
    cat > /etc/systemd/system/observability-agent.service <<'UNIT'
[Unit]
Description=observability-agent — host metrics, logs and OTLP receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/observability-agent --config /etc/observability-agent/agent.json
EnvironmentFile=-/etc/observability-agent/agent.env
Restart=on-failure
RestartSec=5s
TimeoutStopSec=40s
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  fi
  systemctl daemon-reload
  systemctl enable --now observability-agent.service
  report /usr/bin/observability-agent
  /usr/bin/observability-agent --check --config /etc/observability-agent/agent.json || true
}

install_darwin() {
  write_config /usr/local/etc/observability-agent /usr/local/bin
  PLIST=/Library/LaunchDaemons/com.obsagent.observability-agent.plist
  if [ -n "$ENDPOINT" ]; then
    ENVBLOCK=$(printf '  <key>EnvironmentVariables</key>\n  <dict>\n    <key>OBSAGENT_EXPORT_ENDPOINT</key>\n    <string>%s</string>\n  </dict>' "$ENDPOINT")
  else
    ENVBLOCK=""
  fi
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
${ENVBLOCK}
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
  report /usr/local/bin/observability-agent
  /usr/local/bin/observability-agent --check --config /usr/local/etc/observability-agent/agent.json || true
}

case "$OS" in
  linux)  install_linux ;;
  darwin) install_darwin ;;
esac
