// Package integration holds cross-component tests.
//
// It contains no production code. Its tests wire the real supervisor to the
// real host module through the real platform ports, which is the only place
// that combination is exercised: the host module must not import the
// supervisor (the architecture rules forbid it), so a test that lives inside
// either package could only ever check half the interaction.
//
// What these tests are for is the seam. Unit tests prove the host module
// collects correctly and that the supervisor manages lifecycles correctly;
// these prove that a real module plugged into the real supervisor starts,
// collects, degrades, reconfigures and stops as one product.
package integration
