//go:build linux

package logs

import (
	"context"
	"os"
)

// loginTailer reads the login accounting files.
//
// btmp is the reason this exists: failed login attempts are recorded there and
// nowhere else in a form meant to be counted. wtmp is included because the
// successful side of the same story costs almost nothing once the record
// decoder is written, and "289 failures and 257 successes" is a far more
// useful pair of numbers than either alone.
type loginTailer struct {
	state map[string]*loginFileState
}

type loginFileState struct {
	offset int64
	size   int64
}

func newLoginTailer() *loginTailer {
	return &loginTailer{state: map[string]*loginFileState{}}
}

// loginFile pairs a path with what a record in it means. The same struct
// layout carries opposite meanings in the two files, and only the filename
// says which.
type loginFile struct {
	path   string
	failed bool
}

func (t *loginTailer) Read(_ context.Context, s Settings) ([]Record, error) {
	files := s.LoginFiles
	if len(files) == 0 {
		files = defaultLoginFiles()
	}
	var out []Record
	for _, path := range files {
		if len(out) >= s.MaxBatch {
			break
		}
		out = append(out, t.readFile(loginFile{path: path, failed: isFailedLoginFile(path)}, s, s.MaxBatch-len(out))...)
	}
	if len(out) > s.MaxBatch {
		out = out[:s.MaxBatch]
	}
	return out, nil
}

func (t *loginTailer) readFile(lf loginFile, s Settings, budget int) []Record {
	if budget <= 0 {
		return nil
	}
	f, err := os.Open(lf.path)
	if err != nil {
		// btmp is 0600 root on most systems. Denial is a privilege boundary,
		// not a fault, and reporting it every two seconds would be noise.
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}

	cur := t.state[lf.path]
	if cur == nil {
		// Start at the end, as every other reader here does. wtmp on a
		// long-lived host holds months of history and replaying it on each
		// agent restart would say nothing about now.
		t.state[lf.path] = &loginFileState{offset: st.Size(), size: st.Size()}
		return nil
	}
	if st.Size() < cur.size {
		// Rotated. logrotate truncates these rather than renaming, so a
		// shrunken file is the same file emptied.
		cur.offset = 0
	}
	cur.size = st.Size()
	if st.Size() <= cur.offset {
		return nil
	}

	want := int64(budget) * utmpRecordLen
	if avail := st.Size() - cur.offset; want > avail {
		want = avail
	}
	buf := make([]byte, want)
	n, err := f.ReadAt(buf, cur.offset)
	if n == 0 && err != nil {
		return nil
	}

	records, consumed := utmpRecords(buf[:n])
	// A partial record at the tail is left for the next cycle: the file is
	// being appended to while this runs, and decoding half a struct would
	// invent a login that never happened.
	cur.offset += int64(consumed)

	out := make([]Record, 0, len(records))
	for _, r := range records {
		msg := utmpMessage(r, lf.failed)
		if msg == "" {
			continue
		}
		rec := Record{
			Body:   msg,
			Source: SourceLogins,
			File:   lf.path,
			PID:    r.PID,
		}
		// A failed login is a warning, not information: it is the one thing in
		// these files someone sets an alert on.
		if lf.failed {
			rec.Priority, rec.HasPriority = 4, true // LOG_WARNING
		} else {
			rec.Priority, rec.HasPriority = 6, true // LOG_INFO
		}
		out = append(out, rec)
	}
	return out
}

func isFailedLoginFile(path string) bool {
	return len(path) >= 4 && path[len(path)-4:] == "btmp"
}

func defaultLoginFiles() []string {
	return []string{"/var/log/btmp", "/var/log/wtmp"}
}
