// Package architecture holds the agent's executable architecture rules.
//
// It contains no production code. Its tests assert the structural invariants
// that keep the agent one maintainable product: import boundaries between the
// agent shell, the supervisor, the module contract and the platform ports; the
// rule that only the entrypoint chooses a platform adapter; the absence of test
// doubles from production code; and an empty third-party dependency set.
//
// These live as tests rather than as prose because a boundary documented in a
// design document erodes within weeks, while a boundary asserted by a test
// fails the build the first time somebody crosses it.
package architecture
