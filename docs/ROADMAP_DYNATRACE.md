# Dynatrace-style product roadmap (mapped to this agent)

This maps Dynatrace's public architecture ([org repos](https://github.com/orgs/Dynatrace/repositories),
[OneAgent](https://docs.dynatrace.com/docs/platform/oneagent/how-one-agent-works),
[OTel Collector](https://github.com/Dynatrace/dynatrace-otel-collector),
[Operator](https://github.com/Dynatrace/dynatrace-operator),
[OneAgent SDK](https://github.com/Dynatrace/OneAgent-SDK)) onto **this**
repository's stages. OneAgent itself is closed-source; we copy the *shape*,
not their binary.

## Layers (Dynatrace → us)

```
┌─────────────────────────────────────────────────────────────┐
│  Storage / query / AI          Dynatrace SaaS               │
│  (out of agent)                → your platform (later)      │
├─────────────────────────────────────────────────────────────┤
│  Edge ingest                   ActiveGate / OTel Collector  │
│                                → obsagent-intake (demo)     │
│                                → production Telemetry Plane │
├─────────────────────────────────────────────────────────────┤
│  Host agent                    OneAgent (closed)            │
│                                → observability-agent        │
│                                  collectors + native export │
├─────────────────────────────────────────────────────────────┤
│  App instrumentation           OneAgent inject + SDK + OTel │
│                                → otel-engine (+ future SDK) │
├─────────────────────────────────────────────────────────────┤
│  Fleet install                 Operator / Ansible           │
│                                → install.sh / user-data     │
│                                → Stage 15 packaging         │
└─────────────────────────────────────────────────────────────┘
```

## Stage map

| Stage | Your plan | Dynatrace analog | Status |
|---|---|---|---|
| 1 | Shell, supervisor, ports | OneAgent process + lifecycle | **done** |
| 2 | Host metrics | OneAgent OS metrics | **done** |
| 3 | Process | OneAgent process monitoring | **done** |
| 4 | Discovery | Auto-discovery of services/entities | **done** (basic) |
| — | Logs | OneAgent log module | **done** |
| — | Native exporter | OneAgent → cluster (proprietary) | **done** (`obsagent.v1`) |
| — | OTLP export / receive | OTel Collector + app OTLP | **done** |
| — | HTTP checks | Synthetic / extension checks | **done** (`httpcheck`) |
| 6 | Secret scrubber | Redaction in pipeline | next |
| 8 | Network | OneAgent network | planned |
| 9–11 | eBPF / security / profiler | Deep inject / code-level | planned (hard) |
| 12 | Updater | OneAgent auto-update | planned |
| 13 | Resource governor | Agent self-throttling | seam exists |
| 15 | Packaging / installers | Ansible, Operator, bootstrapper | partial (`install.sh`) |

**Near-term order (Dynatrace-inspired, practical):**

1. Harden EC2 install + intake (fleet story) — *you are here*
2. Secret scrubber (Stage 6) before more signal volume
3. Stronger discovery (containers, cloud relationships)
4. Network module (Stage 8)
5. Production intake / Telemetry Plane (replace demo)
6. Updater (Stage 12)
7. Only then eBPF / profiler (Stages 9–11)

Do **not** chase OneAgent auto-inject early. Dynatrace keeps that closed for a
reason; your `otel-engine` + OTel SDKs in apps is the open equivalent.

## Deep dives (three public repos)

### 1. [dynatrace-operator](https://github.com/Dynatrace/dynatrace-operator)

**What it is:** Kubernetes controller that rolls out OneAgent / ActiveGate via
a `DynaKube` CR. Modes: classic fullstack, host-only, app-only injection,
cloud-native (host + inject), plus ActiveGate routing / k8s monitoring.

**What it is not:** The collector. It *deploys* the closed agent.

**Steal for us:**
- One CR / one config model that selects *modes* (host vs app vs both)
- Separate “edge proxy” (ActiveGate) from “host agent”
- CSI / caching only when needed — complexity is optional

**Our analog today:** `install.sh` + systemd + `agent.json`. A future
“operator” is Stage 15+ and only matters when you run on Kubernetes.

### 2. [dynatrace-otel-collector](https://github.com/Dynatrace/dynatrace-otel-collector)

**What it is:** A *verified component set* of the upstream OpenTelemetry
Collector (filelog, hostmetrics, journald, OTLP, prometheus, k8s_*, batch,
memory_limiter, redaction, OTLP exporters, …). Images on GHCR/ECR/Docker Hub,
cosign-signed. Ships to Dynatrace over OTLP.

**What it is not:** A replacement for OneAgent. It is the interoperability
bridge and k8s/log scrape path.

**Steal for us:**
- Keep OTLP as a **bridge**, not the only identity of the product
- Batch + memory limits + redaction as first-class processors
- Monthly cadence / signed artifacts for the collector distro

**Our analog today:** `internal/platform/otlp` + `otel-engine`. Long-term,
pointing `export.otlp` at Alloy / ADOT / a Dynatrace-style distro is valid;
native export stays the default product path.

### 3. [OneAgent-SDK](https://github.com/Dynatrace/OneAgent-SDK)

**What it is:** Language-independent **API spec** (Java as reference) for
custom tracing: remote calls, DB, web in/out, messaging, in-process links,
custom services, request attributes. Language SDKs are thin; **OneAgent does
the real work** when present. Serverless: use OTel instead.

**What it is not:** An open agent. Without OneAgent installed, the SDK is a
no-op / limited.

**Steal for us:**
- Semantic tracers (DB, messaging, RPC) beat generic “span” APIs for operators
- SDK is an *extension surface* after auto paths exist
- Prefer OTel for serverless and for open ecosystems

**Our analog today:** apps → `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318`
→ `otel-engine` → native/OTLP export. A proprietary SDK is optional Stage 11+;
OTel coverage first.

## EC2 path (ready binaries)

Built artifacts:

| File | Use |
|---|---|
| `build/observability-agent-linux-amd64` | Copy to EC2 |
| `build/obsagent-intake-linux-amd64` | Run on intake host |
| `build/observability-agent.exe` | Local Windows test |
| `build/obsagent-intake.exe` | Local Windows test |

Steps: [AWS_AGENT.md](AWS_AGENT.md) · Intake: [INTAKE.md](INTAKE.md)

```powershell
# rebuild anytime
powershell -File packaging/build-linux.ps1
```
