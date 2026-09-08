//go:build windows

package logs

func defaultLogPaths() []string {
	return []string{
		`C:\Windows\Logs\*.log`,
	}
}

func platformSet() Set {
	s := Set{
		Files:    newFileTailer(),
		EventLog: newEventLogReader(),
		Syslog:   newSyslogListener(),
	}
	s.Unsupported = []Unsupported{
		{Source: SourceJournald, Reason: "journald is not available on Windows"},
		{Source: SourceLogins, Reason: "utmp login accounting is a Unix file format"},
		{Source: SourceLastlog, Reason: "the lastlog table is a Linux file format not written on Windows"},
		{Source: SourceArchives, Reason: "atop and sysstat archives are not written on Windows"},
	}
	return s
}
