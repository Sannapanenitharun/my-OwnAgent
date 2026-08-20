package platform

import "strconv"

// Natural key shapes for entity kinds observed by MORE THAN ONE component.
//
// This file exists because of a defect that is invisible until two modules ship
// together. EntityRef is resolved by mapping a natural key onto an identifier,
// so two components that describe the same real thing with DIFFERENT keys
// resolve to two different identifiers — and the entity graph silently forks,
// with half the telemetry hanging off each fork. Nothing fails, nothing logs,
// and the damage is discovered months later by whoever tries to correlate them.
//
// The process module and the discovery module both observe processes. They may
// not import each other, so agreeing by convention would mean two copies of a
// key shape that must stay byte-identical forever. Instead the shape lives here,
// beside the EntityKind it belongs to, because a natural key is part of the
// shared taxonomy for exactly the same reason the kind is.
//
// THE RULE: when a second component starts observing an existing EntityKind, its
// key builder moves here. Until then a kind observed by one module may keep its
// builder in that module. See ADR-0006.
//
// Stability: changing a key shape re-keys every entity of that kind. These
// functions are therefore append-only in spirit — a new field means a new
// function, not an extra key on an existing one.

// ProcessRef builds the natural key for one process INSTANCE.
//
// The four components, and why each is load-bearing:
//
//	boot        the raw start stamp is boot-relative on Linux, so without a boot
//	            discriminator a process started 500 jiffies after one boot and
//	            another started 500 jiffies after the next share a key
//	pid         the handle, which alone is NOT an identity because it is reused
//	start       the platform's RAW start stamp, which is what tells two
//	            consecutive holders of a recycled PID apart; raw rather than
//	            wall-clock because derived times round and can collide
//	executable  the program name, which makes a key human-recognisable and
//	            catches the pathological case of a PID reused within one tick
//
// The command line is deliberately absent: it is attacker-controlled, unbounded,
// and routinely carries credentials, and a natural key may be persisted against
// the entity forever.
func ProcessRef(hostEntity, bootID string, pid int64, startRaw uint64, executable string) EntityRef {
	return EntityRef{
		Kind:   EntityKindProcess,
		Parent: hostEntity,
		Keys: []Attr{
			A("boot", bootID),
			A("pid", strconv.FormatInt(pid, 10)),
			A("start", strconv.FormatUint(startRaw, 10)),
			A("executable", executable),
		},
	}
}
