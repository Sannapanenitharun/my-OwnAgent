# observability-agent

BINARY   := observability-agent
PKG      := github.com/obsagent/observability-agent
VERSION  ?= 0.3.0-stage3
BUILDDIR := build
LDFLAGS  := -s -w -X main.version=$(VERSION)

PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64

.PHONY: all
all: check

## check: everything that must pass before a commit
.PHONY: check
check: fmt vet test crosscompile

.PHONY: fmt
fmt:
	gofmt -l . | tee /dev/stderr | (! read)

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test ./... -count=1

## race: the concurrency gate. Requires cgo and a C toolchain, so it does not
## run on a stock Windows box — run it on Linux or in CI. See docs/READINESS.md.
.PHONY: race
race:
	CGO_ENABLED=1 go test -race ./... -count=1

## stress: shake out order-dependent and timing-sensitive failures
.PHONY: stress
stress:
	go test ./... -count=10

.PHONY: bench
bench:
	go test ./internal/supervisor/ -run '^$$' -bench . -benchmem -benchtime=500x
	go test ./internal/modules/process/ -run '^$$' -bench . -benchmem -benchtime=20x

## scale: process collection cost and footprint at 100 / 1K / 10K / 50K
.PHONY: scale
scale:
	go test ./internal/modules/process/ -run '^$$' -bench 'FullCollection|Reconcile|HighChurn' -benchmem -benchtime=20x
	go test ./internal/modules/process/ -run 'TestStateTableFootprintAtScale|TestMemoryPerTrackedProcessIsBounded|TestGoroutineCountIsIndependentOfProcessCount' -v -count=1

## readers: exercise the REAL platform readers against this machine. This is
## the only gate cross-compilation cannot substitute for.
.PHONY: readers
readers:
	go test ./internal/modules/... -run 'TestReal|TestPlatform|TestWindows|TestDarwin|TestLinux' -v -count=1

## measure: report the supervisor's steady-state footprint
.PHONY: measure
measure:
	go test ./internal/supervisor/ -run TestSteadyStateResourceFootprint -v -count=1

.PHONY: build
build:
	@mkdir -p $(BUILDDIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/$(BINARY) ./cmd/$(BINARY)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/obsagent-intake ./cmd/obsagent-intake

## linux-agent: Linux amd64 agent + intake (for EC2 copy)
.PHONY: linux-agent
linux-agent:
	@mkdir -p $(BUILDDIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/observability-agent-linux-amd64 ./cmd/$(BINARY)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILDDIR)/obsagent-intake-linux-amd64 ./cmd/obsagent-intake

## crosscompile: every supported target must build from any host
.PHONY: crosscompile
crosscompile:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		printf '%-16s' "$$os/$$arch"; \
		if GOOS=$$os GOARCH=$$arch go build -o /dev/null ./... 2>/dev/null; then \
			echo "ok"; \
		else \
			echo "FAILED"; exit 1; \
		fi; \
	done

## release: per-platform binaries with checksums. Ships BOTH the agent and the
## intake sink — packaging/get-intake.sh resolves obsagent-intake-* from these
## same release assets, so omitting them breaks the intake one-liner.
.PHONY: release
release:
	@mkdir -p $(BUILDDIR)/release
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; \
		[ "$$os" = "windows" ] && ext=".exe"; \
		for c in $(BINARY) obsagent-intake; do \
			out=$(BUILDDIR)/release/$$c-$$os-$$arch$$ext; \
			echo "building $$out"; \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/$$c || exit 1; \
		done; \
	done
	cd $(BUILDDIR)/release && sha256sum * > SHA256SUMS

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)

.PHONY: help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
