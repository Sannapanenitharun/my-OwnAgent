//go:build !linux && !windows && !darwin

package logs

func defaultLogPaths() []string { return nil }

func platformSet() Set {
	return Set{
		Syslog: newSyslogListener(),
		Unsupported: []Unsupported{
			{Source: SourceFiles, Reason: "no log file defaults on this OS"},
			{Source: SourceJournald, Reason: "journald is not available on this OS"},
			{Source: SourceEventLog, Reason: "Windows Event Log is not available on this OS"},
			{Source: SourceLogins, Reason: "utmp login accounting is not read on this OS"},
			{Source: SourceLastlog, Reason: "the lastlog table is a Linux file format not written on this OS"},
			{Source: SourceArchives, Reason: "atop and sysstat archives are not written on this OS"},
		},
	}
}
