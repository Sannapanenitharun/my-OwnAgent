//go:build windows

package logs

import (
	"context"
	"syscall"
	"unsafe"
)

var (
	modadvapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procOpenEventLogW              = modadvapi32.NewProc("OpenEventLogW")
	procCloseEventLog              = modadvapi32.NewProc("CloseEventLog")
	procReadEventLogW              = modadvapi32.NewProc("ReadEventLogW")
	procGetNumberOfEventLogRecords = modadvapi32.NewProc("GetNumberOfEventLogRecords")
	procGetOldestEventLogRecord    = modadvapi32.NewProc("GetOldestEventLogRecord")
)

const (
	eventlogForwardsRead = 0x0004
	eventlogSeekRead     = 0x0002
)

type eventlogRecord struct {
	Length              uint32
	Reserved            uint32
	RecordNumber        uint32
	TimeGenerated       uint32
	TimeWritten         uint32
	EventID             uint32
	EventType           uint16
	NumStrings          uint16
	EventCategory       uint16
	ReservedFlags       uint16
	ClosingRecordNumber uint32
	StringOffset        uint32
	UserSidLength       uint32
	UserSidOffset       uint32
	DataLength          uint32
	DataOffset          uint32
}

type eventLogReader struct {
	seen map[string]uint32
}

func newEventLogReader() *eventLogReader {
	return &eventLogReader{seen: map[string]uint32{}}
}

func (r *eventLogReader) Read(_ context.Context, s Settings) ([]Record, error) {
	channels := s.EventLogs
	if len(channels) == 0 {
		channels = []string{"Application", "System"}
	}
	var out []Record
	for _, ch := range channels {
		recs := r.readChannel(ch, s)
		out = append(out, recs...)
		if len(out) >= s.MaxBatch {
			return out[:s.MaxBatch], nil
		}
	}
	return out, nil
}

func (r *eventLogReader) readChannel(name string, s Settings) []Record {
	ptr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil
	}
	h, _, _ := procOpenEventLogW.Call(0, uintptr(unsafe.Pointer(ptr)))
	if h == 0 {
		return nil
	}
	defer procCloseEventLog.Call(h)

	var count, oldest uint32
	procGetNumberOfEventLogRecords.Call(h, uintptr(unsafe.Pointer(&count)))
	procGetOldestEventLogRecord.Call(h, uintptr(unsafe.Pointer(&oldest)))
	if count == 0 {
		return nil
	}
	newest := oldest + count - 1
	last := r.seen[name]
	if last == 0 {
		r.seen[name] = newest
		return nil
	}
	if newest <= last {
		r.seen[name] = newest
		return nil
	}

	buf := make([]byte, 64*1024)
	var read, needed uint32
	flags := uint32(eventlogSeekRead | eventlogForwardsRead)
	ret, _, _ := procReadEventLogW.Call(
		h,
		uintptr(flags),
		uintptr(last+1),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&read)),
		uintptr(unsafe.Pointer(&needed)),
	)
	r.seen[name] = newest
	if ret == 0 || read < uint32(unsafe.Sizeof(eventlogRecord{})) {
		return nil
	}
	return parseEventLogBuffer(buf[:read], name, s.MaxBatch)
}

func parseEventLogBuffer(buf []byte, channel string, max int) []Record {
	var out []Record
	off := 0
	for off+int(unsafe.Sizeof(eventlogRecord{})) <= len(buf) && len(out) < max {
		rec := (*eventlogRecord)(unsafe.Pointer(&buf[off]))
		if rec.Length < uint32(unsafe.Sizeof(eventlogRecord{})) {
			break
		}
		end := off + int(rec.Length)
		if end > len(buf) {
			break
		}
		msg := eventLogStrings(buf[off:end], rec)
		if msg != "" {
			out = append(out, Record{Body: msg, Source: SourceEventLog, Channel: channel})
		}
		off = end
	}
	return out
}

func eventLogStrings(buf []byte, rec *eventlogRecord) string {
	if rec.NumStrings == 0 || int(rec.StringOffset) >= len(buf) {
		return ""
	}
	u := buf[rec.StringOffset:]
	// UTF-16LE until double NUL, first insertion string only.
	n := 0
	for n+1 < len(u) {
		if u[n] == 0 && u[n+1] == 0 {
			break
		}
		n += 2
	}
	if n < 2 {
		return ""
	}
	words := make([]uint16, n/2)
	for i := 0; i < len(words); i++ {
		words[i] = uint16(u[i*2]) | uint16(u[i*2+1])<<8
	}
	return syscall.UTF16ToString(words)
}
