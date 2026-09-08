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
		Files:  newFileTailer(),
		Syslog: newSyslogListener(),
		Unsupported: []Unsupported{
			{Source: SourceJournald, Reason: "journald is not available on macOS"},
			{Source: SourceEventLog, Reason: "Windows Event Log is not available on macOS"},
			{Source: SourceLogins, Reason: "utmp login accounting is not written on macOS"},
			{Source: SourceLastlog, Reason: "the lastlog table is a Linux file format not written on macOS"},
			{Source: SourceArchives, Reason: "atop and sysstat archives are not written on macOS"},
		},
	}
}
