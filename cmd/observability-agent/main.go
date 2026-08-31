// Command observability-agent is the single enterprise observability agent
// binary.
//
// One installation, one binary, one service, one identity, one configuration
// model, one telemetry pipeline — and many independently managed modules behind
// it. This file does nothing but parse flags, build the platform ports, and
// hand control to the agent shell.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/obsagent/observability-agent/internal/agent"
	"github.com/obsagent/observability-agent/internal/config"
	"github.com/obsagent/observability-agent/internal/imds"
	"github.com/obsagent/observability-agent/internal/localui"
	"github.com/obsagent/observability-agent/internal/module"
	"github.com/obsagent/observability-agent/internal/modules/container"
	"github.com/obsagent/observability-agent/internal/modules/discovery"
	"github.com/obsagent/observability-agent/internal/modules/host"
	"github.com/obsagent/observability-agent/internal/modules/httpcheck"
	"github.com/obsagent/observability-agent/internal/modules/logs"
	"github.com/obsagent/observability-agent/internal/modules/otelengine"
	"github.com/obsagent/observability-agent/internal/modules/process"
	"github.com/obsagent/observability-agent/internal/modules/statsd"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
	"github.com/obsagent/observability-agent/internal/platform/native"
	"github.com/obsagent/observability-agent/internal/platform/otlp"
	"github.com/obsagent/observability-agent/internal/platform/scrub"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		// Errors are already logged in structured form where they occur; this
		// line is the last-resort message for failures that happen before the
		// logger exists.
		fmt.Fprintln(os.Stderr, "observability-agent:", err)
		os.Exit(1)
	}
}

func run(args []string, errOut *os.File) error {
	fs := flag.NewFlagSet("observability-agent", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var (
		configPath  = fs.String("config", os.Getenv(config.EnvConfigPath), "path to the agent configuration file; empty uses built-in defaults")
		logLevel    = fs.String("log-level", "info", "log level: debug, info, warn, error")
		logFormat   = fs.String("log-format", "text", "text or json")
		uiListen    = fs.String("ui-listen", envOr("OBSAGENT_UI_LISTEN", "127.0.0.1:8181"), "local status UI address; off disables")
		checkConfig = fs.Bool("check", false, "validate configuration and module wiring, then exit without starting")
		showVersion = fs.Bool("version", false, "print version information and exit")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		fmt.Println(versionString())
		return nil
	}

	level, err := parseLevel(*logLevel)
	if err != nil {
		return err
	}
	logger, err := newLogger(*logFormat, level)
	if err != nil {
		return err
	}

	loader := config.NewLoader()
	cfg, err := loader.LoadFile(*configPath)
	if err != nil {
		return err
	}

	ports, hostDetails, err := buildPorts(cfg)
	if err != nil {
		return err
	}

	a, err := agent.New(agent.Options{
		ConfigPath: *configPath,
		Config:     &cfg,
		Loader:     loader,
		Ports:      ports,
		Logger:     logger,
		Modules:    modules(),
		UIListen:   *uiListen,
		Host:       hostDetails,
	})
	if err != nil {
		return err
	}

	if *checkConfig {
		cfg := a.Config()
		logger.Info("configuration is valid",
			"revision", cfg.Revision,
			"schema_version", cfg.SchemaVersion,
			"modules", len(cfg.Modules))
		return nil
	}

	logger.Info("observability-agent starting", "version", versionString())
	return a.Run(context.Background())
}

// modules returns the modules compiled into this build.
//
// Adding a collector is exactly this: one line here, and one entry in the
// grant list below. The supervisor resolves start order from manifests, so this
// list is unordered and no wiring elsewhere changes.
//
// Still to come, each behind the same module contract: network, ebpf,
// security, profiler, secret-scrubber, updater.
func modules() []module.Module {
	return []module.Module{
		host.New(),
		process.New(),
		discovery.New(),
		container.New(),
		logs.New(),
		httpcheck.New(),
		otelengine.New(),
		statsd.New(),
	}
}

// grants is the reference stand-in for an IAM policy: which capability may hold
// which permission. It is written out explicitly rather than derived from each
// module's manifest, because "grant whatever the module asks for" is not an
// authorization system — it is the absence of one, and it would make the
// fail-closed admission path untestable.
var grants = map[string][]platform.Permission{
	string(host.ID):       {host.PermissionRead},
	string(process.ID):    {process.PermissionRead},
	string(discovery.ID):  {discovery.PermissionRead},
	string(container.ID):  {container.PermissionRead},
	string(logs.ID):       {logs.PermissionRead},
	string(httpcheck.ID):  {httpcheck.PermissionProbe},
	string(otelengine.ID): {otelengine.PermissionReceive},
	string(statsd.ID):     {statsd.PermissionReceive},
}

// buildPorts constructs the platform ports.
//
// The in-process adapters remain the local sink (status UI, tests). When
// export.native.endpoint is set, they are wrapped by the first-party HTTPS
// JSON writer (Datadog-style). When export.otlp.endpoint is set, OTLP wraps
// as well so both intakes can receive the same observations.
func buildPorts(cfg config.Config) (platform.Ports, localui.HostDetails, error) {
	capRuntime := inproc.NewCapabilityRuntime()
	for capability, perms := range grants {
		capRuntime.Grant(capability, perms...)
	}

	ident := imds.Resolve(context.Background(), os.Getenv("OBSAGENT_HOST_ID"), nil)
	hostDetails := localui.HostDetails{
		InstanceID:     ident.InstanceID,
		InstanceName:   ident.InstanceName,
		Region:         ident.Region,
		AZ:             ident.AZ,
		InstanceType:   ident.InstanceType,
		AMIID:          ident.AMIID,
		AccountID:      ident.AccountID,
		LocalHostname:  ident.LocalHostname,
		PublicHostname: ident.PublicHostname,
		LocalIPv4:      ident.LocalIPv4,
		PublicIPv4:     ident.PublicIPv4,
	}
	if ident.InstanceID != "" {
		hostDetails.CloudProvider = "aws"
	}

	mem := inproc.NewTelemetry()
	// Scrub credential-shaped substrings once, before any exporter sees them.
	var tel platform.Telemetry = scrub.Wrap(mem)
	resource := []platform.Attr{
		platform.A("service.name", "observability-agent"),
		platform.A("service.version", version),
	}
	resource = append(resource, ident.ResourceAttributes()...)

	if ep := strings.TrimSpace(cfg.Export.Native.Endpoint); ep != "" {
		spool := strings.TrimSpace(os.Getenv("OBSAGENT_EXPORT_SPOOL"))
		if spool == "" {
			if runtime.GOOS == "windows" {
				spool = filepath.Join(os.TempDir(), "obsagent-export-spool")
			} else {
				spool = filepath.Join("/var/lib/observability-agent", "spool")
			}
		}
		exp := native.New(tel, native.Config{
			Endpoint:    ep,
			Headers:     cfg.Export.Native.Headers,
			Timeout:     cfg.Export.Native.Timeout.Std(),
			Interval:    cfg.Export.Native.Interval.Std(),
			MaxBatch:    cfg.Export.Native.MaxBatch,
			Compression: cfg.Export.Native.Compression,
			Resource:    resource,
			SpoolDir:    spool,

			TraceSampleRate: cfg.Export.Native.TraceSampleRate,
		})
		exp.Start()
		tel = exp
	}
	if ep := strings.TrimSpace(cfg.Export.OTLP.Endpoint); ep != "" {
		exp := otlp.New(tel, otlp.Config{
			Endpoint: ep,
			Protocol: cfg.Export.OTLP.Protocol,
			Headers:  cfg.Export.OTLP.Headers,
			Timeout:  cfg.Export.OTLP.Timeout.Std(),
			Interval: cfg.Export.OTLP.Interval.Std(),
			MaxBatch: cfg.Export.OTLP.MaxBatch,
			Resource: resource,
		})
		exp.Start()
		tel = exp
	}

	return platform.Ports{
		Runtime:   capRuntime,
		Telemetry: tel,
		Identity: inproc.NewIdentity(
			os.Getenv("OBSAGENT_AGENT_ID"),
			os.Getenv("OBSAGENT_TENANT_ID"),
			ident.InstanceID,
		),
		Clock: platform.NewSystemClock(),
	}, hostDetails, nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", s)
	}
}

func newLogger(format string, level slog.Level) (*slog.Logger, error) {
	opts := &slog.HandlerOptions{Level: level}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	case "text", "":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	default:
		return nil, fmt.Errorf("unknown log format %q", format)
	}
}

func versionString() string {
	revision := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				revision = setting.Value
			}
		}
	}
	return fmt.Sprintf("observability-agent %s (%s)", version, revision)
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
