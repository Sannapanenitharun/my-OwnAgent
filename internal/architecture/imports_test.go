// Package architecture holds executable architecture rules.
//
// Import boundaries are the only thing keeping "many independently managed
// modules" from decaying into a tangle that must be released as one unit. A
// boundary documented in prose erodes in weeks; a boundary asserted by a test
// fails the build the first time someone crosses it. These rules are therefore
// tests, not documentation.
package architecture

import (
	"go/build"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/obsagent/observability-agent"

// targetPlatforms are the OS/arch pairs the agent supports. Imports are checked
// under every one of them, so a build-tagged file that reaches across a
// boundary on Linux is caught while developing on Windows.
var targetPlatforms = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
}

// pkg is a package's import surface for one platform.
type pkg struct {
	importPath  string
	dir         string
	imports     []string
	testImports []string
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("could not locate the module root from %s: %v", root, err)
	}
	return root
}

// loadPackages returns every package in the module, for one target platform.
func loadPackages(t *testing.T, goos, goarch string) map[string]pkg {
	t.Helper()
	root := repoRoot(t)

	ctx := build.Default
	ctx.GOOS = goos
	ctx.GOARCH = goarch
	ctx.CgoEnabled = false

	out := map[string]pkg{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if name == ".git" || name == "testdata" || name == "docs" {
			return filepath.SkipDir
		}

		p, err := ctx.ImportDir(path, 0)
		if err != nil {
			// A directory with no Go files for this platform is expected.
			if _, ok := err.(*build.NoGoError); ok {
				return nil
			}
			return nil
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		importPath := modulePath
		if rel != "." {
			importPath = modulePath + "/" + filepath.ToSlash(rel)
		}
		out[importPath] = pkg{
			importPath:  importPath,
			dir:         path,
			imports:     p.Imports,
			testImports: append(append([]string{}, p.TestImports...), p.XTestImports...),
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("no packages found for %s/%s", goos, goarch)
	}
	return out
}

func short(importPath string) string {
	return strings.TrimPrefix(importPath, modulePath+"/")
}

// forbidden lists, per package, the packages it must never import.
//
// The shape of this table is the architecture: dependencies point inward, from
// the agent shell, through the supervisor, to the module contract, and finally
// to the leaf contracts and the platform ports. Nothing points back out.
var forbidden = map[string][]string{
	// The ports layer is the innermost ring. If it depended on anything in the
	// agent, swapping in a real platform adapter would drag agent code along.
	"internal/platform": {
		"internal/agent", "internal/supervisor", "internal/module",
		"internal/config", "internal/health", "internal/diagnostics",
	},

	// Leaf contracts. These are shared vocabulary; if they could reach the
	// supervisor, every module would transitively depend on it.
	"internal/diagnostics": {"internal/agent", "internal/supervisor", "internal/module", "internal/config", "internal/health"},
	"internal/health":      {"internal/agent", "internal/supervisor", "internal/module", "internal/config"},
	"internal/config":      {"internal/agent", "internal/supervisor", "internal/module", "internal/health"},

	// The module contract must never see the supervisor. A module that can
	// reach the supervisor can reach every other module through it, which is
	// exactly the hidden coupling the contract exists to prevent.
	"internal/module": {"internal/agent", "internal/supervisor"},

	// The supervisor must not depend on the shell that wires it, or on the
	// local UI that reads it.
	"internal/supervisor": {"internal/agent", "internal/localui"},

	// guard is a leaf utility shared by the supervisor and by collector
	// modules. If it could reach any of them it would stop being shareable.
	"internal/guard": {
		"internal/agent", "internal/supervisor", "internal/module",
		"internal/config", "internal/health", "internal/diagnostics", "internal/platform",
	},

	// Collector modules depend on the contracts and on nothing above them.
	// The rule that matters most is module-to-module: a collector that could
	// import another collector would couple two independently released units
	// and defeat the whole modular design.
	"internal/modules/host":       {"internal/agent", "internal/supervisor"},
	"internal/modules/process":    {"internal/agent", "internal/supervisor"},
	"internal/modules/discovery":  {"internal/agent", "internal/supervisor"},
	"internal/modules/logs":       {"internal/agent", "internal/supervisor"},
	"internal/modules/httpcheck":  {"internal/agent", "internal/supervisor"},
	"internal/modules/otelengine": {"internal/agent", "internal/supervisor"},

	// IMDS is a leaf used by the entrypoint to resolve EC2 identity. It must
	// not reach into the agent shell or collectors.
	"internal/imds": {
		"internal/agent", "internal/supervisor", "internal/module",
		"internal/modules", "internal/localui",
	},
	"internal/localui": {
		"internal/agent", "internal/modules",
	},
	// The OTLP adapter is a platform adapter: it may import platform ports
	// and nothing above them. Only the entrypoint constructs it.
	"internal/platform/otlp": {
		"internal/agent", "internal/supervisor", "internal/module",
		"internal/config", "internal/health", "internal/diagnostics",
		"internal/modules", "internal/localui", "internal/imds",
	},
	"internal/platform/native": {
		"internal/agent", "internal/supervisor", "internal/module",
		"internal/config", "internal/health", "internal/diagnostics",
		"internal/modules", "internal/localui", "internal/imds",
	},
}

// moduleRoot is the parent of every collector module. Any package beneath it is
// subject to the module-to-module isolation rule below.
const moduleRoot = "internal/modules"

// TestModulesCannotImportEachOther is the rule that keeps modules
// independently maintainable.
//
// Two collectors that share a helper today share a release cadence tomorrow. If
// they genuinely need common code it belongs in a contract package both may
// depend on — never in one of them.
func TestModulesCannotImportEachOther(t *testing.T) {
	for _, target := range targetPlatforms {
		t.Run(target.goos+"/"+target.goarch, func(t *testing.T) {
			for path, p := range loadPackages(t, target.goos, target.goarch) {
				self := short(path)
				if !strings.HasPrefix(self, moduleRoot+"/") {
					continue
				}
				mine := moduleNameOf(self)
				for _, imp := range p.imports {
					other := short(imp)
					if !strings.HasPrefix(other, moduleRoot+"/") {
						continue
					}
					if moduleNameOf(other) != mine {
						t.Errorf("module %s imports module %s; modules must not depend on each other",
							mine, moduleNameOf(other))
					}
				}
			}
		})
	}
}

// moduleNameOf returns the module name from a path under internal/modules.
func moduleNameOf(p string) string {
	rest := strings.TrimPrefix(p, moduleRoot+"/")
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[:i]
	}
	return rest
}

func TestPackagesRespectImportBoundaries(t *testing.T) {
	for _, target := range targetPlatforms {
		t.Run(target.goos+"/"+target.goarch, func(t *testing.T) {
			pkgs := loadPackages(t, target.goos, target.goarch)
			for path, p := range pkgs {
				rules, ok := forbidden[short(path)]
				if !ok {
					continue
				}
				for _, imp := range p.imports {
					for _, banned := range rules {
						if short(imp) == banned || strings.HasPrefix(short(imp), banned+"/") {
							t.Errorf("%s imports %s, which the architecture forbids", short(path), short(imp))
						}
					}
				}
			}
		})
	}
}

// TestNoProductionCodeImportsTestDoubles guards the one mistake that would make
// every other guarantee unverifiable: shipping a fake in the real binary.
func TestNoProductionCodeImportsTestDoubles(t *testing.T) {
	doubles := []string{"internal/platform/clockfake"}

	for _, target := range targetPlatforms {
		t.Run(target.goos+"/"+target.goarch, func(t *testing.T) {
			for path, p := range loadPackages(t, target.goos, target.goarch) {
				for _, imp := range p.imports {
					for _, d := range doubles {
						if short(imp) == d {
							t.Errorf("%s imports the test double %s in non-test code", short(path), d)
						}
					}
				}
			}
		})
	}
}

// TestOnlyTheEntrypointChoosesAdapters asserts that the decision of WHICH
// platform adapter to use is made in exactly one place.
//
// This is what makes the ports design real rather than decorative: when the
// enterprise platform adapters arrive, the blast radius is one function in main
// plus internal/platform, and no module, the supervisor, or the agent shell has
// to move. See docs/adr/0001-ports-and-adapters.md.
func TestOnlyTheEntrypointChoosesAdapters(t *testing.T) {
	adapters := []string{"internal/platform/inproc", "internal/platform/otlp", "internal/platform/native"}
	allowed := map[string]bool{
		"cmd/observability-agent":  true,
		"internal/platform/inproc": true,
		"internal/platform/otlp":   true,
		"internal/platform/native": true,
	}

	for _, target := range targetPlatforms {
		t.Run(target.goos+"/"+target.goarch, func(t *testing.T) {
			for path, p := range loadPackages(t, target.goos, target.goarch) {
				if allowed[short(path)] {
					continue
				}
				for _, imp := range p.imports {
					for _, adaptersPkg := range adapters {
						if short(imp) == adaptersPkg {
							t.Errorf("%s selects a platform adapter directly; only the entrypoint may", short(path))
						}
					}
				}
			}
		})
	}
}

// TestNoThirdPartyDependencies keeps the agent's supply chain empty.
//
// Every dependency is code that ships to a customer host inside a privileged
// process, and every dependency is a supply-chain surface and an SBOM entry.
// Stage 1 needs none, so it has none, and adding one becomes a deliberate,
// reviewable act rather than a drive-by `go get`.
func TestNoThirdPartyDependencies(t *testing.T) {
	for _, target := range targetPlatforms {
		t.Run(target.goos+"/"+target.goarch, func(t *testing.T) {
			for path, p := range loadPackages(t, target.goos, target.goarch) {
				// The OTLP adapter is the one package allowed a third-party
				// OTLP protobuf implementation. The rest of the agent stays
				// stdlib-only. This build encodes OTLP by hand, so the
				// allowlist is currently unused — it is the seam, not a
				// licence to import elsewhere.
				if strings.HasPrefix(short(path), "internal/platform/otlp") {
					continue
				}
				all := append(append([]string{}, p.imports...), p.testImports...)
				for _, imp := range all {
					if strings.HasPrefix(imp, modulePath) {
						continue
					}
					// Standard library import paths have no dot in their first
					// element; everything else is a module dependency.
					first, _, _ := strings.Cut(imp, "/")
					if strings.Contains(first, ".") {
						t.Errorf("%s imports third-party package %s", short(path), imp)
					}
				}
			}
		})
	}
}

// TestGoModDeclaresNoRequirements is the belt to the previous test's braces: an
// indirect requirement could appear in go.mod without any import yet existing.
func TestGoModDeclaresNoRequirements(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require") {
			t.Errorf("go.mod declares a requirement: %q", line)
		}
	}
}

// forbiddenSources are operating-system interfaces no collector may read,
// mapped to why.
//
// These are not performance rules. Each one is a place where an agent that
// wandered in would be exfiltrating exactly the secrets it exists to protect —
// /proc/PID/environ is the single richest source of credentials on a typical
// host, and /proc/PID/mem is the whole address space. "We don't read that" is a
// security property, and security properties that live only in a comment erode
// the first time someone needs one more field.
// The path needles include the closing quote because these paths are always
// built as a literal suffix ( ... + "/io" ). Matching the bare word instead
// would flag /proc/meminfo for containing /proc/mem — which the first run of
// this test duly did.
var forbiddenSources = map[string]string{
	`/environ"`:                 "process environment variables are the richest source of credentials on a host",
	`/mem"`:                     "process memory must never be read",
	`/maps"`:                    "process memory layout must never be read",
	`/smaps"`:                   "smaps is both a memory-layout disclosure and a denial of service at scale",
	"ReadProcessMemory":         "reading another process's memory is prohibited regardless of platform",
	"NtQueryInformationProcess": "the documented query APIs are sufficient; this one is the gateway to PEB reads",
}

// TestCollectorsDoNotReadForbiddenSources asserts the prohibition in code.
//
// It is a source-text check, which is a blunt instrument — and deliberately so.
// A reviewer adding a /proc/PID/environ read has to also delete a line from this
// table, which turns an easy mistake into an explicit, reviewable decision.
func TestCollectorsDoNotReadForbiddenSources(t *testing.T) {
	root := repoRoot(t)
	modulesDir := filepath.Join(root, "internal", "modules")

	err := filepath.WalkDir(modulesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(root, path)
		for _, line := range strings.Split(string(body), "\n") {
			trimmed := strings.TrimSpace(line)
			// Comments explaining WHY something is not read are the point of the
			// rule, not a violation of it.
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			for needle, why := range forbiddenSources {
				if strings.Contains(line, needle) {
					t.Errorf("%s references %q in non-comment code: %s",
						filepath.ToSlash(rel), needle, why)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestEveryPackageIsDocumented keeps the codebase navigable. A package comment
// is where the "why" of a package lives; without one, the next engineer has to
// reconstruct intent from call sites.
func TestEveryPackageIsDocumented(t *testing.T) {
	root := repoRoot(t)
	ctx := build.Default
	ctx.GOOS = "linux"
	ctx.GOARCH = "amd64"

	var undocumented []string
	for path, p := range loadPackages(t, "linux", "amd64") {
		bp, err := ctx.ImportDir(p.dir, build.ImportComment)
		if err != nil {
			continue
		}
		if bp.Doc == "" {
			rel, _ := filepath.Rel(root, p.dir)
			undocumented = append(undocumented, filepath.ToSlash(rel)+" ("+short(path)+")")
		}
	}
	sort.Strings(undocumented)
	for _, u := range undocumented {
		t.Errorf("package has no doc comment: %s", u)
	}
}
