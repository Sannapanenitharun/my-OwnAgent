package logs

import "context"

// Record is one collected log line, before redaction is applied by the
// emitter. Body must not be forwarded unredacted.
type Record struct {
	Body    string
	Source  Source
	File    string
	Channel string

	// PID and Process name the process this record came from: the one
	// holding the file open for writing when it was found by discovery, or
	// the sender journald recorded. Set together or not at all: attribution
	// that is only half known is worse than none, because a PID with no name
	// reads as a number nobody can look up.
	PID     int
	Process string

	// Unit and Container are journald's own join keys, stamped by the daemon
	// rather than read out of the message.
	Unit      string
	Container string

	// Priority is the syslog level the SOURCE declared -- journald's PRIORITY
	// field. HasPriority distinguishes "the sender said emerg" (0) from "the
	// sender said nothing", which a bare int cannot: zero is a real level.
	Priority    int
	HasPriority bool
}

// Reader is one log source. A platform that cannot provide it is absent from
// the Set, not implemented with an empty read.
type Reader interface {
	Read(ctx context.Context, s Settings) ([]Record, error)
}

// Unsupported names a source this platform cannot provide.
type Unsupported struct {
	Source Source
	Reason string
}

// Set is the platform's available readers.
type Set struct {
	Files       Reader
	Journald    Reader
	EventLog    Reader
	Logins      Reader
	Lastlog     Reader
	Archives    Reader
	Unsupported []Unsupported
}

func (s Set) Has(src Source) bool {
	switch src {
	case SourceFiles:
		return s.Files != nil
	case SourceJournald:
		return s.Journald != nil
	case SourceEventLog:
		return s.EventLog != nil
	case SourceLogins:
		return s.Logins != nil
	case SourceLastlog:
		return s.Lastlog != nil
	case SourceArchives:
		return s.Archives != nil
	}
	return false
}

func (s Set) Reader(src Source) Reader {
	switch src {
	case SourceFiles:
		return s.Files
	case SourceJournald:
		return s.Journald
	case SourceEventLog:
		return s.EventLog
	case SourceLogins:
		return s.Logins
	case SourceLastlog:
		return s.Lastlog
	case SourceArchives:
		return s.Archives
	}
	return nil
}
