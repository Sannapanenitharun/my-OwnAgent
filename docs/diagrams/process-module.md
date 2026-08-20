# Process module diagrams

## 1. Component structure

```
                  ┌─────────────────────────────────────────┐
                  │           supervisor                     │
                  │  Start · Stop · Health · Config · Throttle│
                  └────────────────────┬────────────────────┘
                                       │ module.Module contract
                  ┌────────────────────▼────────────────────┐
                  │          process.Module                  │
                  │      ONE collection goroutine            │
                  └────────────────────┬────────────────────┘
                                       │
     ┌──────────┬──────────┬───────────┼──────────┬──────────┬──────────┐
     ▼          ▼          ▼           ▼          ▼          ▼          ▼
 ┌────────┐┌────────┐┌──────────┐┌──────────┐┌────────┐┌─────────┐┌────────┐
 │ reader ││ filter ││ lifecycle││ identity ││ rollup ││  emit   ││ health │
 │  Set   ││        ││  store   ││ resolver ││        ││         ││        │
 └───┬────┘└────────┘└──────────┘└────┬─────┘└────────┘└────┬────┘└────────┘
     │                                 │                     │
     │ build-tagged, one per platform  │ platform ports      │
     ▼                                 ▼                     ▼
 ┌─────────────────────┐      ┌────────────────┐    ┌────────────────┐
 │ linux   /proc       │      │ Identity +     │    │ Telemetry      │
 │ windows toolhelp    │      │ EntityResolver │    │ Plane          │
 │ darwin  kern.proc   │      └────────────────┘    └────────────────┘
 │ other   unsupported │
 └─────────────────────┘
```

The module contains no OS-specific code. Exactly one build-tagged file supplies
the reader set; every other file compiles identically everywhere.

## 2. Collection sequence — the cost model

The order IS the cost model. Work done on a process that will be discarded is the
minimum needed to discard it.

```
 1. ENUMERATE ─────────────────────────── O(all processes), one bulk operation
    │  Linux:   readdir /proc, then one /proc/PID/stat per admitted PID
    │  Windows: one toolhelp snapshot, then OpenProcess per admitted PID
    │  Darwin:  one sysctl for the whole table
    │
    │  ┌── PID pre-filter runs HERE, before any per-process work.
    │  └── The only filter that can; that is why it exists.
    ▼
 2. RECONCILE ─────────────────────────── O(all processes), 1 allocation total
    │  detect PID reuse · compute CPU deltas · admit to state · reap exits
    ▼
 3. AGGREGATE ─────────────────────────── over EVERYTHING discovered
    │  process.count and the state distribution are facts about the machine,
    │  so filters must not change them
    ▼
 4. CHEAP FILTERS ─────────────────────── name · state · user · min.cpu · min.memory
    ▼
 5. BOUNDED SELECTION ─────────────────── max_processes, deterministic
    │  included ▸ kernel/init ▸ CPU ▸ memory ▸ name ▸ PID
    ▼
 6. EXPENSIVE READS ───────────────────── O(selected) only
    │  io · open files · executable path · command line
    ▼
 7. ENTITY RESOLUTION ─────────────────── O(new instances), cached per instance
    ▼
 8. ROLLUP BY EXECUTABLE ──────────────── N processes ▸ ≤ max_executables series
    ▼
 9. EMIT ──────────────────────────────── aggregates ▸ events ▸ rollups ▸ top-N
    ▼
10. RECORD STATISTICS
```

Measured consequence: 1,000 processes with `max_processes=10` performs exactly
**10** of each expensive read, not 1,000.

## 3. Process identity and PID reuse

```
        t0                    t1                    t2
        │                     │                     │
  PID 1234 ──── nginx ────────┤                     │
  start=1000                  │ exits               │
                              │                     │
                        PID 1234 ──── redis ────────┤
                        start=9000                  │

  InstanceKey                InstanceKey
  {boot-A, 1234, 1000}       {boot-A, 1234, 9000}
        │                            │
        └────────── DIFFERENT ───────┘
```

What the module does at t1→t2, in one cycle:

```
   observe PID 1234
        │
        ├─ tracked? ── no ──▶ START  (admit, seed CPU baseline)
        │
        └─ yes ─┬─ same instance key? ── yes ──▶ RUNNING (compute deltas)
                │
                └─ no ──▶ EXIT the old  ─┐
                          START the new  ├─▶ + REPLACED
                          reset baselines┘
```

Without this, redis inherits nginx's cumulative CPU counter. Since redis has used
less CPU than nginx had, the delta is negative, and depending on the arithmetic
that becomes either a suppressed sample or an enormous wrapped one. Both are
wrong; neither announces itself.

## 4. State lifecycle and eviction

```
   ┌──────────────┐  observed   ┌──────────────┐  not observed  ┌──────────┐
   │  discovered  │────────────▶│   tracked    │───────────────▶│  exited  │
   └──────┬───────┘             └──────┬───────┘                └────┬─────┘
          │                            │                             │
          │ table full                 │ PID reused                  │ state
          ▼                            ▼                             │ freed
   ┌──────────────┐             ┌──────────────┐                     │ SAME
   │  untracked   │             │   replaced   │                     │ CYCLE
   │              │             └──────────────┘                     ▼
   │ counted in   │                                          ┌───────────────┐
   │ aggregates,  │                                          │ recentExits   │
   │ no deltas,   │                                          │ name ▸ time   │
   │ no entity    │                                          │ bounded by    │
   └──────────────┘                                          │ TTL and 4096  │
                                                             └───────────────┘
```

Two bounds, because there are two ways to grow:

- **`max_tracked`** bounds live instances. Admission is in ascending PID order —
  low PIDs are long-lived system services, high PIDs are churn, so under pressure
  the module sheds churn and keeps services.
- **`recentExits`** is keyed by executable *name*, not PID, so a churn storm of
  uniquely-named processes cannot inflate it. Bounded by TTL and by a hard 4096.

Exited state is released in the cycle its disappearance is noticed, not on a
timer.

## 5. Cardinality: what the rollup buys

```
   10,000 processes                      40 distinct executables
   ├─ nginx      ×  500  ┐
   ├─ postgres   ×  200  │  rollupBy      ┌─ nginx     instances=500  rss=Σ
   ├─ python     × 3,000 ├──────────────▶ ├─ postgres  instances=200  rss=Σ
   ├─ java       ×   80  │                ├─ python    instances=3000 rss=Σ
   └─ ...                ┘                └─ ...
                                                   │
                                    selectExecutables(max_executables)
                                                   │
                                                   ▼
                                          ≤ 128 × 9 metrics
                                          = 258 series measured
```

Sums, not averages, for everything additive: 500 workers at 8 MB each is 4 GB of
real memory, and an average would hide it. `process.instances` accompanies every
rollup, because without it "nginx is using 4 GB" cannot be told apart from "one
nginx worker is using 4 GB".

## 6. Back-pressure

```
  PressureNone      ┌───────────────────────────────────────────────┐  interval ×1
                    │ aggregate │ lifecycle │ rollups │ detail+topN │
                    └───────────────────────────────────────────────┘

  PressureModerate  ┌─────────────────────────────────┐               interval ×2
                    │ aggregate │ lifecycle │ rollups │  ✂ detail
                    └─────────────────────────────────┘

  PressureHigh      ┌───────────────────────┐                         interval ×4
                    │ aggregate │ lifecycle │              ✂ rollups
                    └───────────────────────┘

  PressureCritical  ┌───────────┐                                     interval ×8
                    │ aggregate │                       ✂ lifecycle
                    └───────────┘
```

Whole classes are dropped, lowest first, so what survives is internally
consistent. An agent that shed a uniform fraction of everything would emit
rollups whose instance counts did not match their memory sums — telemetry that is
not merely reduced but wrong.

## 7. Failure isolation

```
                       ┌── cycle runs inside guard.Call ──┐
                       │   one deadline, one panic guard   │
                       └────────────────┬─────────────────┘
                                        │
   ┌──────────┬──────────┬──────────────┼───────────┬──────────────┐
   ▼          ▼          ▼              ▼           ▼              ▼
 PID 100   PID 101    PID 102        PID 103    reader panics  deadline
   OK      denied     exited           OK           │           passes
   │          │          │             │            │              │
   │     counted as  counted as        │      recovered,      cycle SUSPENDED
   │     "denied"    churn             │      diagnostic,     until the read
   │          │          │             │      next cycle      genuinely returns
   ▼          ▼          ▼             ▼      retries              │
 ┌──────────────────────────────────────┐                          ▼
 │  cycle SUCCEEDS. Module stays healthy │              one parked goroutine
 │  Agent unaffected.                    │              ONCE, not one per
 └──────────────────────────────────────┘              interval forever
```

A single cycle failing never tells the supervisor the module failed. A process
collector that restarted every time `/proc` hiccupped would be worse than one
that reports a degraded cycle and tries again in thirty seconds.

## 8. Data flow — metrics versus events

```
                        observation
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
       ROLLED UP BY                  PER INSTANCE
       EXECUTABLE                    (pid, ppid, start, lifetime,
              │                       path, command line)
              ▼                             ▼
       ┌─────────────┐              ┌─────────────┐
       │   METRICS   │              │   EVENTS    │
       │             │              │             │
       │ entity =    │              │ entity =    │
       │   HOST      │              │   HOST +    │
       │             │              │   PROCESS   │
       │ bounded by  │              │ bounded by  │
       │ max_        │              │ max_events_ │
       │ executables │              │ per_cycle   │
       └──────┬──────┘              └──────┬──────┘
              └─────────────┬──────────────┘
                            ▼
                 platform.Telemetry port
                 (one pipeline, no second exporter)
```

Metrics carry the host entity: binding a series to a process entity would
recreate exactly the cardinality the rollup exists to avoid. Process entities
appear on events, where the record has a lifetime.
