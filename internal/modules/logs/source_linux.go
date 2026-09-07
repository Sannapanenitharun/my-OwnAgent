//go:build linux

package logs

// defaultLogPaths is Ubuntu-shaped, and deliberately more than the obvious
// four. It was rebuilt from an inventory of a live host rather than from a
// list of well-known locations, which is how the last three entries got here:
// none of them appears in the usual write-ups.
//
// TWO PATTERNS THAT USED TO MISS:
//
// DEPTH. "/var/log/*/*.log" is exactly one directory deep, so
// /var/log/amazon/ssm/amazon-ssm-agent.log was invisible -- as would be a
// Kubernetes node's /var/log/pods/<pod>/<container>/0.log.
//
// SUFFIX. Requiring ".log" hides files that follow the Apache naming
// convention (/var/log/cups/access_log) and files that have no suffix at all
// (/var/log/dmesg, /var/log/sysstat/sar26). Matching them means matching
// binaries too -- wtmp, btmp, lastlog and atop sit in the same directories --
// which is why the tailer sniffs every new file and refuses the ones that are
// not text. That guard is what makes these patterns safe rather than reckless.
func defaultLogPaths() []string {
	return []string{
		// The rsyslog-written trio. syslog and messages have no .log suffix
		// and are named individually rather than swept up by a wildcard,
		// because they are the ones that must never be missed.
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/auth.log",

		// Everything else rsyslog or a package writes at the top level:
		// kern.log, dpkg.log, cloud-init*.log, ufw.log, fail2ban.log,
		// alternatives.log, and anything a newly installed service adds.
		"/var/log/*.log",

		// One and two directories down: nginx/, apache2/, postgresql/,
		// mysql/, audit/, unattended-upgrades/ at the first level;
		// amazon/ssm/ and pods/<pod>/ at the second.
		"/var/log/*/*.log",
		"/var/log/*/*/*.log",

		// Container runtimes, whose files are named by ID rather than by
		// service.
		"/var/lib/docker/containers/*/*-json.log",
		"/var/log/containers/*.log",
		"/var/log/pods/*/*/*.log",

		// Suffix-less text logs found on a real host. Each is named rather
		// than matched by a bare "/var/log/*" wildcard, which would sweep in
		// wtmp, btmp, lastlog and every rotated archive.
		"/var/log/dmesg",
		"/var/log/*/access_log",
		"/var/log/*/error_log",
	}
}

func platformSet() Set {
	s := Set{
		Files:    newFileTailer(),
		Journald: newJournaldTailer(),
		Logins:   newLoginTailer(),
	}
	s.Unsupported = []Unsupported{
		{Source: SourceEventLog, Reason: "Windows Event Log is not available on Linux"},
	}
	return s
}
