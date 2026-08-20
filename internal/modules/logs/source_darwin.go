//go:build darwin

package logs

func defaultLogPaths() []string {
	return []string{
		"/var/log/system.log",
		"/var/log/install.log",
	}
}

func platformSet() Set {
	return Set{
		Files: newFileTailer(),
		Unsupported: []Unsupported{
			{Source: SourceJournald, Reason: "journald is not available on macOS"},
			{Source: SourceEventLog, Reason: "Windows Event Log is not available on macOS"},
		},
	}
}
