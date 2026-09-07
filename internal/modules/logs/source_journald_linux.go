//go:build linux

package logs

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// journaldTailer follows systemd journal files by parsing their object arena.
//
// It used to scan appended bytes for the literal "MESSAGE=". On a host where
// journald is the primary sink that collected 30 lines out of 39,485 while
// reporting success every cycle. See journalfile.go for why the scan could not
// be repaired.
type journaldTailer struct {
	state map[string]*journalFileState
}

type journalFileState struct {
	// offset is the next object to examine. Objects are append-only, so this
	// is all the position the walk needs.
	offset int64
	// size detects rotation the same way the file tailer does: a journal that
	// shrank is a new file wearing an old name.
	size int64
}

func newJournaldTailer() *journaldTailer {
	return &journaldTailer{state: map[string]*journalFileState{}}
}

func (t *journaldTailer) Read(_ context.Context, s Settings) ([]Record, error) {
	files := journalFiles()
	if len(files) == 0 {
		return nil, nil
	}
	var out []Record
	for _, path := range files {
		recs := t.readFile(path, s, s.MaxBatch-len(out))
		out = append(out, recs...)
		if len(out) >= s.MaxBatch {
			return out[:s.MaxBatch], nil
		}
	}
	return out, nil
}

func (t *journaldTailer) readFile(path string, s Settings, budget int) []Record {
	if budget <= 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}

	h, err := readJournalHeader(f)
	if err != nil {
		// Not a journal, or one written by a version whose header this does
		// not recognise. Silence is correct: journalFiles globs a directory,
		// so a stray file there is not a fault.
		return nil
	}

	cur := t.state[path]
	if cur == nil {
		// First sight starts at the tail, exactly as the file tailer starts at
		// end-of-file: a 2.5 GB journal replayed on every agent restart would
		// bury the live view in history nobody asked for.
		t.state[path] = &journalFileState{offset: h.tailObjectOffset, size: st.Size()}
		return nil
	}
	if st.Size() < cur.size {
		cur.offset = h.headerSize
	}
	cur.size = st.Size()

	entries, next, _ := readJournalEntries(f, h, cur.offset, journalWanted, budget)
	cur.offset = next

	out := make([]Record, 0, len(entries))
	for _, e := range entries {
		rec := Record{
			Body:   e.Fields["MESSAGE"],
			Source: SourceJournald,
		}
		// Attribution the KERNEL set, not something parsed out of the text.
		// _PID and _COMM are stamped by journald from the sending process's
		// credentials, so unlike anything recovered from a line's contents
		// they cannot be spoofed by what the process chose to write.
		if pid, err := strconv.Atoi(e.Fields["_PID"]); err == nil && pid > 0 {
			rec.PID = pid
		}
		if comm := e.Fields["_COMM"]; comm != "" {
			rec.Process = comm
		} else if id := e.Fields["SYSLOG_IDENTIFIER"]; id != "" {
			rec.Process = id
		}
		if unit := e.Fields["_SYSTEMD_UNIT"]; unit != "" {
			rec.Unit = unit
		}
		// Docker's journald driver stamps the container, which is the same
		// join key the json-file path recovers from the file name.
		if cid := e.Fields["CONTAINER_ID"]; cid != "" {
			rec.Container = cid
		}
		// PRIORITY is the level the sender declared. It outranks reading a
		// level out of the message text, which is a heuristic over free-form
		// output and cannot be better than the source's own statement.
		if p, err := strconv.Atoi(e.Fields["PRIORITY"]); err == nil && p >= 0 && p <= 7 {
			rec.Priority, rec.HasPriority = p, true
		}
		if rec.Body == "" {
			continue
		}
		out = append(out, rec)
	}
	return out
}

func journalFiles() []string {
	roots := []string{"/run/log/journal", "/var/log/journal"}
	var out []string
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			// Rotated journals end in "@<seqnum>.journal" and hold only
			// history; the live file is the plain one. Reading the archives
			// would replay the past on every restart.
			if strings.HasSuffix(path, ".journal") && !strings.Contains(filepath.Base(path), "@") {
				out = append(out, path)
			}
			return nil
		})
	}
	return out
}
