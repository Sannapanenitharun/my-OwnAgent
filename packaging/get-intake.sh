# Install and run obsagent-intake as a systemd service (Linux).
# Default listen: 0.0.0.0:8090 (avoids Coroot / other UIs on :8089).
#
#   curl -fsSL https://raw.githubusercontent.com/Sannapanenitharun/my-OwnAgent/main/packaging/get-intake.sh \
#     | sudo sh -s --
#
# Then point the agent at it:
#   echo 'OBSAGENT_EXPORT_ENDPOINT=http://127.0.0.1:8090' | sudo tee /etc/observability-agent/agent.env
#   sudo systemctl restart observability-agent
set -eu

REPO=${OBSAGENT_REPO:-Sannapanenitharun/my-OwnAgent}
VERSION=${OBSAGENT_VERSION:-latest}
LISTEN=${INTAKE_LISTEN:-0.0.0.0:8090}
STORE=${INTAKE_STORE:-/var/lib/obsagent-intake}
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

ASSET="obsagent-intake-linux-${ARCH}"
if [ "$VERSION" = "latest" ]; then
  API="https://api.github.com/repos/${REPO}/releases/latest"
else
  API="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
URL=$(curl -fsSL "$API" | sed -n 's/.*"browser_download_url": *"\([^"]*'"${ASSET}"'[^"]*\)".*/\1/p' | head -n 1)
if [ -z "$URL" ]; then
  echo "could not find ${ASSET} in release assets" >&2
  exit 1
fi

echo "downloading $URL"
curl -fsSL "$URL" -o "$TMP/obsagent-intake"
install -d -m 0755 "$PREFIX/bin" "$STORE"
install -m 0755 "$TMP/obsagent-intake" "$PREFIX/bin/obsagent-intake"

cat > /etc/systemd/system/obsagent-intake.service <<EOF
[Unit]
Description=obsagent-intake — native obsagent.v1 sink
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PREFIX}/bin/obsagent-intake -listen ${LISTEN} -store ${STORE}
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
