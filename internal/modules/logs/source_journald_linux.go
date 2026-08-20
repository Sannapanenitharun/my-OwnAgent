//go:build linux

package logs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// journaldTailer follows systemd journal files from their current end and
// extracts MESSAGE= payloads. It does not parse the journal index; it scans
// newly appended bytes, which is enough to follow live logs without cgo.
type journaldTailer struct {
	state map[string]*fileState
}

func newJournaldTailer() *journaldTailer {
	return &journaldTailer{state: map[string]*fileState{}}
}

func (t *journaldTailer) Read(_ context.Context, s Settings) ([]Record, error) {
	files := journalFiles()
	if len(files) == 0 {
		return nil, nil
	}
	var out []Record
	for _, path := range files {
		recs := t.readFile(path, s)
		out = append(out, recs...)
		if len(out) >= s.MaxBatch {
			return out[:s.MaxBatch], nil
		}
	}
	return out, nil
}

func (t *journaldTailer) readFile(path string, s Settings) []Record {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	cur := t.state[path]
	if cur == nil {
		t.state[path] = &fileState{offset: st.Size(), size: st.Size()}
		return nil
	}
	if st.Size() < cur.size {
		cur.offset = 0
	}
	if st.Size() == cur.offset {
		return nil
	}
	limit := st.Size() - cur.offset
	max := int64(s.MaxBytesPerS)
	if max > 0 && limit > max {
		limit = max
	}
	buf := make([]byte, limit)
	n, err := f.ReadAt(buf, cur.offset)
	if n == 0 && err != nil {
		return nil
	}
	buf = buf[:n]
	cur.offset += int64(n)
	cur.size = st.Size()
	return extractJournalMessages(buf, s.MaxBatch)
}

func journalFiles() []string {
	roots := []string{"/run/log/journal", "/var/log/journal"}
	var out []string
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".journal") {
				out = append(out, path)
			}
			return nil
		})
	}
	return out
}
