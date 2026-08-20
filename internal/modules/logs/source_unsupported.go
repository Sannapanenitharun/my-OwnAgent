//go:build !linux && !windows && !darwin

package logs

func defaultLogPaths() []string { return nil }

func platformSet() Set {
	return Set{
		Unsupported: []Unsupported{
			{Source: SourceFiles, Reason: "no log file defaults on this OS"},
			{Source: SourceJournald, Reason: "journald is not available on this OS"},
			{Source: SourceEventLog, Reason: "Windows Event Log is not available on this OS"},
		},
	}
}
