#!/bin/sh
# One-line install for Amazon Linux / Ubuntu EC2:
#
#   curl -fsSL https://raw.githubusercontent.com/Sannapanenitharun/my-OwnAgent/main/packaging/get.sh \
#     | sudo sh -s -- https://INTAKE_HOST:8080
#
# Optional env:
#   OBSAGENT_VERSION=v0.3.0   pin a release tag (default: latest)
#   OBSAGENT_REPO=owner/name  override GitHub repo
set -eu

ENDPOINT=${1:-}
REPO=${OBSAGENT_REPO:-Sannapanenitharun/my-OwnAgent}
VERSION=${OBSAGENT_VERSION:-latest}
PREFIX=${PREFIX:-/usr}
SYSCONF=${SYSCONF:-/etc/observability-agent}

if [ -z "$ENDPOINT" ]; then
  echo "usage: curl -fsSL .../packaging/get.sh | sudo sh -s -- https://intake.example.com:8080" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *)
    echo "unsupported arch: $(uname -m)" >&2
    exit 1
    ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (sudo)" >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ "$VERSION" = "latest" ]; then
  API="https://api.github.com/repos/${REPO}/releases/latest"
else
  API="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi

echo "resolving release from ${API}"
ASSET_URL=$(curl -fsSL "$API" | sed -n 's/.*"browser_download_url": *"\([^"]*observability-agent-linux-'"$ARCH"'[^"]*\)".*/\1/p' | head -n 1)
if [ -z "$ASSET_URL" ]; then
  echo "could not find observability-agent-linux-${ARCH} in release assets" >&2
  echo "publish a GitHub release that includes that binary, or set OBSAGENT_VERSION" >&2
  exit 1
fi

BIN="$TMP/observability-agent"
echo "downloading $ASSET_URL"
curl -fsSL "$ASSET_URL" -o "$BIN"
chmod 0755 "$BIN"

RAW="https://raw.githubusercontent.com/${REPO}/main/packaging"
curl -fsSL "$RAW/observability-agent.service" -o "$TMP/observability-agent.service"
curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/agent.example.json" -o "$TMP/agent.example.json" || true

install -d -m 0755 "$PREFIX/bin"
install -d -m 0755 "$SYSCONF"
install -m 0755 "$BIN" "$PREFIX/bin/observability-agent"

if [ ! -f "$SYSCONF/agent.json" ]; then
  if [ -f "$TMP/agent.example.json" ]; then
    install -m 0644 "$TMP/agent.example.json" "$SYSCONF/agent.json"
  else
    printf '%s\n' '{"schema_version":1,"modules":{"host":{"enabled":true},"process":{"enabled":true},"logs":{"enabled":true},"otel-engine":{"enabled":true},"discovery":{"enabled":true}}}' > "$SYSCONF/agent.json"
    chmod 0644 "$SYSCONF/agent.json"
  fi
fi

printf 'OBSAGENT_EXPORT_ENDPOINT=%s\n' "$ENDPOINT" > "$SYSCONF/agent.env"
chmod 0600 "$SYSCONF/agent.env"

install -m 0644 "$TMP/observability-agent.service" /etc/systemd/system/observability-agent.service
systemctl daemon-reload
systemctl enable --now observability-agent.service

echo "installed $PREFIX/bin/observability-agent → $ENDPOINT"
"$PREFIX/bin/observability-agent" --check --config "$SYSCONF/agent.json" || true
