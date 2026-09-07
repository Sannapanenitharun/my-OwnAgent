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
	}
	s.Unsupported = []Unsupported{
		{Source: SourceJournald, Reason: "journald is not available on Windows"},
		{Source: SourceLogins, Reason: "utmp login accounting is a Unix file format"},
	}
	return s
}
