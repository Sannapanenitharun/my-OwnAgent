# AWS — agent only

This is the **host agent** path. There is no cloud-account UI and no inventory
service. Storage and query stay outside the agent.

The default ship path is the agent's **own HTTPS JSON exporter** (the same
shape as Datadog's Agent: collect, batch, gzip, POST to an intake). OTLP is
optional interoperability with Grafana Alloy, the OpenTelemetry Collector, or
Datadog's OTLP intake.

## One-line install (auto OS/arch)

**Linux or macOS**

```bash
curl -fsSL https://raw.githubusercontent.com/Sannapanenitharun/my-OwnAgent/main/packaging/get.sh | sudo sh -s -- https://INTAKE_HOST:8080
```

Detects `linux`/`darwin` and `amd64`/`arm64`, downloads the matching release
binary, installs a service (systemd or launchd), and points export at your intake.

**Windows** (PowerShell as Administrator)

```powershell
$env:OBSAGENT_EXPORT_ENDPOINT='https://INTAKE_HOST:8080'; irm https://raw.githubusercontent.com/Sannapanenitharun/my-OwnAgent/main/packaging/get.ps1 | iex
```

## Many EC2s

Install the **same** `observability-agent` binary and config on each instance.

- One binary, one config model.
- `OBSAGENT_AGENT_ID` / `OBSAGENT_TENANT_ID` are optional and can be the same
  across the fleet.
- Hosts are distinguished by **EC2 instance id**, not by a new key per machine.

## Host identity

| Source | When it is used |
|---|---|
| `OBSAGENT_HOST_ID` | If set, always. Operator override. |
| IMDS `instance-id` (`i-…`) | If env is unset **and** the agent is on EC2 with metadata reachable. |
| Unresolved | Otherwise. The agent still collects; it does **not** invent an id from hostname, IP, or MAC. |

When IMDS is reachable the exporter also attaches (if present): `cloud.provider=aws`,
`cloud.region`, `cloud.availability_zone`, `host.type`, `cloud.account.id`,
`host.image.id`. Missing fields are omitted.

That matches Datadog's agent-side rule: prefer `i-0abc…` over `ip-10-0-1-5`.

No AWS access keys are required on the instance for IMDS. IMDS is a link-local
query (`169.254.169.254`). If the instance blocks IMDS, set `OBSAGENT_HOST_ID`
or leave it unresolved.

## Export (native JSON, Datadog-style)

Empty `export.native.endpoint` means **no native export** (local UI only unless
OTLP is also set). Set it to **your** intake:

```json
"export": {
  "native": {
    "endpoint": "https://intake.example.com",
    "compression": "gzip",
    "timeout": "10s",
    "interval": "5s",
    "max_batch": 1000
  }
}
```

Or:

```bash
export OBSAGENT_EXPORT_ENDPOINT=https://intake.example.com
export OBSAGENT_EXPORT_HEADERS='X-API-Key=secret'
```

The exporter POSTs gzip JSON to `/v1/logs`, `/v1/metrics`, and `/v1/traces`.
Each body is `obsagent.v1`: `host` is the EC2 instance id when IMDS resolved it,
never a hostname. Collectors do not call this HTTP client; they emit through
the Telemetry port.

Headers belong in env or a secrets-injected file, not in chat logs.

## Export (OTLP, optional)

Empty `export.otlp.endpoint` means no OTLP export. Set it to a collector:

```json
"export": {
  "otlp": {
    "endpoint": "http://alloy.internal:4318",
    "protocol": "http/protobuf"
  }
}
```

Or:

```bash
export OBSAGENT_OTLP_ENDPOINT=http://alloy.internal:4318
# optional ingest headers: OBSAGENT_OTLP_HEADERS='Authorization=Bearer tok'
```

The exporter POSTs `/v1/metrics`, `/v1/logs` and `/v1/traces`. It must **not**
point at the agent's own OTLP receiver (`127.0.0.1:4318` when `otel-engine` is
enabled on that address) — configuration validation rejects that loop.

Reach CloudWatch / X-Ray by pointing this endpoint at ADOT or Alloy, not with a
native AWS exporter in the agent.

## Application traces

`otel-engine` listens on `127.0.0.1:4318` by default. Apps on the instance:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

The receiver is localhost-only unless `listen` is changed. eBPF auto-instrumentation
is not in this build.

## Local UI

The agent serves a status page for **this host only** (not a fleet console):

```bash
observability-agent --config agent.json
# open http://127.0.0.1:8181
```

It shows host id (`i-…` on EC2), module health, CPU/memory/process gauges, and
diagnostics. Disable with `--ui-listen=off`. Bind elsewhere with
`--ui-listen=0.0.0.0:8181` or `OBSAGENT_UI_LISTEN`.

## Install on an instance

### 1. Build Linux binaries (from Windows)

```powershell
powershell -File packaging/build-linux.ps1
# produces build/observability-agent-linux-amd64
#          build/obsagent-intake-linux-amd64
```

For Graviton: `powershell -File packaging/build-linux.ps1 arm64`

### 2. Start intake (any reachable host)

```bash
./obsagent-intake-linux-amd64 -listen 0.0.0.0:8080 -api-key secret -store ./intake-data
```

Note the host's private IP or DNS, e.g. `http://10.0.1.20:8080`.

### 3. Copy agent to EC2 and install

Amazon Linux 2023 / Ubuntu. Open outbound HTTP/HTTPS to the intake. IMDS must
be reachable (default on EC2); no AWS access keys required for identity.

```bash
scp build/observability-agent-linux-amd64 ec2-user@INSTANCE:/tmp/observability-agent
scp packaging/install.sh agent.example.json packaging/observability-agent.service ec2-user@INSTANCE:/tmp/

ssh ec2-user@INSTANCE
cd /tmp
chmod +x observability-agent install.sh
sudo ./install.sh ./observability-agent http://10.0.1.20:8080
echo 'OBSAGENT_EXPORT_HEADERS=X-API-Key=secret' | sudo tee -a /etc/observability-agent/agent.env
sudo systemctl restart observability-agent
```

### 4. Verify

```bash
sudo systemctl status observability-agent
sudo journalctl -u observability-agent -f
curl -s http://127.0.0.1:8181/api/status
# on the intake host:
curl -s http://127.0.0.1:8080/
```

Host id in status / payloads should be `i-…` from IMDS.

Optional: enable HTTP checks in `/etc/observability-agent/agent.json` (see
[HTTPCHECK.md](HTTPCHECK.md)), then restart the service.

See also [packaging/user-data.example.yaml](../packaging/user-data.example.yaml)
and [INTAKE.md](INTAKE.md).
