//go:build linux

package logs

func defaultLogPaths() []string {
	return []string{
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/secure",
		"/var/log/auth.log",
		"/var/log/cloud-init.log",
	}
}

func platformSet() Set {
	s := Set{
		Files:    newFileTailer(),
		Journald: newJournaldTailer(),
	}
	s.Unsupported = []Unsupported{
		{Source: SourceEventLog, Reason: "Windows Event Log is not available on Linux"},
	}
	return s
}
