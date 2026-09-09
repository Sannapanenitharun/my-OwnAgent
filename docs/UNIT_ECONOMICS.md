# Unit economics

Cost per business unit — `$/order`, `$/tenant`, `$/transaction` — computed at
the intake from telemetry the agent already sends.

> **Every number produced here is an estimate.** Rates come from the cloud
> provider's public **list price**. A host covered by a Reserved Instance, a
> Savings Plan, Spot capacity or an enterprise discount costs something else,
> frequently less than half. This is not a bill and must never be presented as
> one.
>
> What *is* reliable is the **allocation**. If two containers divide a host
> 70/30 by measured consumption, that ratio holds whatever the host actually
> cost. So this answers *"which workload is expensive"* correctly, while
> answering *"what is the bill"* only approximately — and the first is the
> question an engineer can act on.

## The shape of it

```
                cost attributable to the thing
  unit cost  =  ───────────────────────────────
                     count of the thing
```

Three feeds, owned by three different groups, which is the real reason unit
economics is hard:

| Feed | Source | Who owns it |
|---|---|---|
| Rate | provider price list (`internal/pricing`) | nobody — it is published |
| Allocation | agent telemetry, split at the intake | infrastructure |
| **Denominator** | **your application** | **whoever ships the product** |

The third is the one nothing can infer. No infrastructure telemetry knows which
counter represents the thing your business sells.

## Turning it on

```sh
obsagent-intake \
  -store /var/lib/obsagent-intake \
  -pricing \
  -unit-metric orders.processed
```

- `-pricing` enables rate lookup. **Off by default** — the first lookup for a
  region downloads roughly 300 MB, and the numbers are list prices.
- `-unit-metric` names the series to divide by. Empty means cost only, no unit
  economics.
- `-store` doubles as the price-list cache directory. Without it, catalogs are
  held in memory and re-fetched on restart.

Environment equivalents: `INTAKE_PRICING`, `INTAKE_UNIT_METRIC`.

## Supplying the denominator

**No new ingest surface is needed.** The agent already accepts application
metrics, and either path works:

```sh
# StatsD — set `listen` on the statsd module first, it is off by default
echo "orders.processed:1|c" | nc -u -w0 127.0.0.1 8125
```

```
# or OTLP/HTTP to the agent's receiver
POST http://127.0.0.1:4318/v1/metrics
```

Anything the agent forwards becomes a series at the intake, and any series can
be the denominator.

### Counters and gauges mean different things

The distinction is invisible in the number, so it is carried in the output:

| Kind | Example | Denominator used | Result |
|---|---|---|---|
| counter | `orders.processed` | rate derived from the history ring | **cost per order** |
| gauge | `tenants.active` | the current value | **cost per tenant per hour** |

A counter's raw value is cumulative and useless as a denominator — dividing an
hourly cost by every order since the process started answers nothing. The rate
comes from the sample history instead, and a **counter reset produces no unit
cost at all** rather than a negative or absurd one.

## How the split works

Host cost is divided between containers by measured consumption, weighted
**60% CPU / 40% memory** — the ratio Datadog publishes for standard instances.
There is no ground truth for how much of a machine's price is "the cores", so
matching a documented practice beats inventing a different arbitrary number.

```
share  = 0.60 × (container cores ÷ host cores)
       + 0.40 × (container bytes ÷ host bytes)

cost   = host $/hour × share
idle   = host $/hour − Σ cost
```

The share is measured against the host's **capacity**, not against the sum of
the containers. Dividing by the sum would always total 100% and idle would never
appear — and idle is usually the number worth acting on. On the demo host above,
two containers accounted for 37.5% of an `m5.xlarge` and **62.5% of it was paid
for and unused**.

## Reading the panel

| State | Means |
|---|---|
| no panel | The host has no `cloud.region` / `host.type`, so it has no list price. Bare metal, or a laptop. |
| `NO RATE YET` | The shape is known, the price list is still downloading. Fills in shortly. |
| `LIST PRICE ESTIMATE` | A rate was found. Read the caveat at the top of this page. |

A missing rate never renders as `$0.00`. "Free" and "unknown" are different
facts and the code keeps them apart deliberately.

## What this is not

- **Not a billing pipeline.** No CUR or FOCUS import, no amortisation, no
  reconciliation with an invoice. That is a different feed and a larger project.
- **Not aware of your discounts.** See the warning at the top.
- **Not idle-vs-waste aware.** Separating *reserved but unused* from *never
  reserved* needs Kubernetes requests and limits, which the agent does not yet
  collect. Until then, "idle" means "capacity no container was consuming".
- **Not multi-cloud.** Only the AWS price list is implemented. The `RateSource`
  interface is the seam where another provider goes.

## Where the pieces live

| Path | Role |
|---|---|
| `internal/pricing` | Fetches, filters and caches provider price lists |
| `internal/pricing/aws.go` | The AWS Price List Bulk API reader |
| `internal/fleet/cost.go` | Splits host cost, computes the unit metric |
| `internal/fleet/fleet.html` | The cost panel |

Run `OBSPROBE=1 go test ./internal/pricing/ -run TestLiveAWSFetch -v -timeout 15m`
to check the parser against the live price list; it is the only thing that
notices if AWS renames a column.
