package logs

import "context"

// Record is one collected log line, before redaction is applied by the
// emitter. Body must not be forwarded unredacted.
type Record struct {
	Body    string
	Source  Source
	File    string
	Channel string
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
	}
	return nil
}
