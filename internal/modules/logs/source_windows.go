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
	}
	return s
}
