#!/bin/sh
# Install and run obsagent-intake as a systemd service (Linux).
# Default listen: 0.0.0.0:8090 (avoids Coroot / other UIs on :8089).
#
#   curl -fsSL https://github.com/Sannapanenitharun/my-OwnAgent/releases/latest/download/get-intake.sh | sudo bash
#
# Then point the agent at it in the same one-line style:
#   curl -fsSL https://github.com/Sannapanenitharun/my-OwnAgent/releases/latest/download/get.sh \
#     | sudo bash -s -- http://127.0.0.1:8090
#
# Optional env:
#   OBSAGENT_VERSION=v0.4.2   pin a release (default: latest)
#   OBSAGENT_REPO=owner/name
#   INTAKE_LISTEN=0.0.0.0:8090
#   INTAKE_STORE=/var/lib/obsagent-intake
#   INTAKE_API_KEY=secret     require X-API-Key on every request
set -eu

REPO=${OBSAGENT_REPO:-Sannapanenitharun/my-OwnAgent}
VERSION=${OBSAGENT_VERSION:-latest}
LISTEN=${INTAKE_LISTEN:-0.0.0.0:8090}
STORE=${INTAKE_STORE:-/var/lib/obsagent-intake}
API_KEY=${INTAKE_API_KEY:-}
PREFIX=${PREFIX:-/usr}

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (sudo)" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

# Release assets directly: no api.github.com, so no 60/hour rate limit.
if [ "$VERSION" = "latest" ]; then
  DL="https://github.com/${REPO}/releases/latest/download"
else
  DL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

ASSET="obsagent-intake-linux-${ARCH}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "downloading $DL/$ASSET"
curl -fsSL "$DL/$ASSET" -o "$TMP/obsagent-intake" || {
  echo "could not download $DL/$ASSET" >&2
  exit 1
}
install -d -m 0755 "$PREFIX/bin" "$STORE"
install -m 0755 "$TMP/obsagent-intake" "$PREFIX/bin/obsagent-intake"

if [ -n "$API_KEY" ]; then
  printf 'INTAKE_API_KEY=%s\n' "$API_KEY" > /etc/obsagent-intake.env
  chmod 0600 /etc/obsagent-intake.env
fi

cat > /etc/systemd/system/obsagent-intake.service <<EOF
[Unit]
Description=obsagent-intake — native obsagent.v1 sink
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PREFIX}/bin/obsagent-intake -listen ${LISTEN} -store ${STORE}
EnvironmentFile=-/etc/obsagent-intake.env
Restart=on-failure
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now obsagent-intake.service
echo "intake listening on http://${LISTEN} store=${STORE}"
curl -fsS "http://127.0.0.1:${LISTEN##*:}/healthz" || true
