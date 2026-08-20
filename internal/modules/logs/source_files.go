package logs

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// fileTailer follows configured paths from the current end of each file so a
// restart does not re-ship history. Rotation (size shrinks) resets to offset 0.
type fileTailer struct {
	state map[string]*fileState
}

type fileState struct {
	offset int64
	size   int64
}

func newFileTailer() *fileTailer {
	return &fileTailer{state: map[string]*fileState{}}
}

func (t *fileTailer) Read(_ context.Context, s Settings) ([]Record, error) {
	paths := s.Paths
	if len(paths) == 0 {
		paths = defaultLogPaths()
	}
	var out []Record
	opened := 0
	for _, pattern := range paths {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			matches = []string{pattern}
		}
		if len(matches) == 0 {
			matches = []string{pattern}
		}
		for _, path := range matches {
			if excluded(path, s.Exclude) {
				continue
			}
			if opened >= s.MaxFiles {
				break
			}
			recs, ok := t.readPath(path, s)
			if ok {
				opened++
			}
			out = append(out, recs...)
			if len(out) >= s.MaxBatch {
				return out[:s.MaxBatch], nil
			}
		}
	}
	return out, nil
}

func (t *fileTailer) readPath(path string, s Settings) ([]Record, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return nil, false
	}
	cur := t.state[path]
	if cur == nil {
		// First sight: start at end so existing content is not re-shipped.
		t.state[path] = &fileState{offset: st.Size(), size: st.Size()}
		return nil, true
	}
	if st.Size() < cur.size {
		cur.offset = 0
	}
	if _, err := f.Seek(cur.offset, io.SeekStart); err != nil {
		return nil, true
	}
	limit := int64(s.MaxBytesPerS)
	if limit <= 0 {
		limit = 256 * 1024
	}
	r := io.LimitReader(f, limit)
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, s.MaxLineBytes+1)
	var out []Record
	consumed := cur.offset
	for sc.Scan() {
		line := sc.Text()
		consumed += int64(len(sc.Bytes()) + 1)
		out = append(out, Record{Body: line, Source: SourceFiles, File: path})
		if len(out) >= s.MaxBatch {
			break
		}
	}
	cur.offset = consumed
	if cur.offset > st.Size() {
		cur.offset = st.Size()
	}
	cur.size = st.Size()
	return out, true
}

func excluded(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, p := range patterns {
		if p == path || p == base {
			return true
		}
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
		if strings.Contains(path, p) && strings.Contains(p, string(filepath.Separator)) {
			return true
		}
	}
	return false
}
