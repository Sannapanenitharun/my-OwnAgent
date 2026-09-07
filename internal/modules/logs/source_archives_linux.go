//go:build linux

package logs

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// archiveTailer reports what historical archives exist on the host and what
// window each one covers.
//
// It exists because the answer to "we don't read atop" was previously kept in
// a survey document rather than in the agent, and a decision that lives only
// in prose is one nobody can act on at three in the morning. When an incident
// predates the agent's installation, the operator's first question is whether
// anything on the box recorded that window. This source answers it.
//
// It reports COVERAGE, not contents. See atop.go for why the payloads are
// deliberately left undecoded, and what would be required to change that.
//
// Each archive is reported once per agent run. The current day's file is still
// being appended to, so its window is a floor rather than a final answer --
// which the message says, rather than quietly re-reporting the same file every
// two seconds for the rest of the day.
type archiveTailer struct {
	reported map[string]bool
	now      func() time.Time
}

func newArchiveTailer() *archiveTailer {
	return &archiveTailer{reported: map[string]bool{}, now: time.Now}
}

// defaultArchivePaths are the binary history formats found on a stock Ubuntu
// host. Only atop's chain is walked; the others are reported as present, with
// their size and age, because that is all that can be said about them without
// a version-locked struct table.
func defaultArchivePaths() []string {
	return []string{
		"/var/log/atop/atop_*",
		"/var/log/sysstat/sa[0-9][0-9]",
	}
}

// maxArchivesPerCycle bounds the work of a single read. A month of retention
// is ~31 atop files and ~31 sysstat files; the cap is above that and well
// below anything that would make a cycle expensive.
const maxArchivesPerCycle = 16

func (t *archiveTailer) Read(_ context.Context, s Settings) ([]Record, error) {
	patterns := s.ArchivePaths
	if len(patterns) == 0 {
		patterns = defaultArchivePaths()
	}

	var paths []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		paths = append(paths, matches...)
	}
	// Oldest first, so a per-cycle cap works through the backlog in a stable
	// order instead of re-picking an arbitrary subset.
	sort.Strings(paths)

	out := make([]Record, 0, 8)
	done := 0
	for _, path := range paths {
		if t.reported[path] {
			continue
		}
		if done >= maxArchivesPerCycle || len(out) >= s.MaxBatch {
			break
		}
		done++
		t.reported[path] = true
		if rec, ok := t.describe(path); ok {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (t *archiveTailer) describe(path string) (Record, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Record{}, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() || st.Size() == 0 {
		return Record{}, false
	}

	rec := Record{
		Source:      SourceArchives,
		File:        path,
		Priority:    6, // LOG_INFO
		HasPriority: true,
	}

	h, err := readAtopHeader(f)
	if err != nil {
		// Not atop, or not a version whose header this understands. Say what
		// is knowable -- that the file exists, how big it is, how recent --
		// and do not guess at the rest.
		rec.Body = "binary history archive " + path + ", " +
			strconv.FormatInt(st.Size(), 10) + " bytes, last written " +
			st.ModTime().UTC().Format(time.RFC3339) +
			"; contents not decoded (no reader for this format)"
		return rec, true
	}

	span := walkAtopRecords(f, h, st.Size())
	if span.Samples == 0 {
		rec.Body = "atop archive " + path + " (atop " +
			strconv.Itoa(h.Major) + "." + strconv.Itoa(h.Minor) +
			") holds no complete samples"
		return rec, true
	}

	body := "atop archive " + path + " covers " +
		span.First.Format(time.RFC3339) + " to " + span.Last.Format(time.RFC3339) +
		" (" + strconv.Itoa(span.Samples) + " samples"
	if span.Interval > 0 {
		body += " at " + strconv.Itoa(span.Interval) + "s"
	}
	body += ", atop " + strconv.Itoa(h.Major) + "." + strconv.Itoa(h.Minor) +
		"); per-process payloads not decoded"

	// Today's archive is still being appended to, so the window above is a
	// floor rather than a final answer. Saying so is the difference between
	// "this host recorded nothing after 15:07" and "this is what it had
	// recorded by the time we looked".
	if t.now().Sub(span.Last) < 2*time.Hour {
		body += "; still being written"
	}

	// A walk that did not land on EOF is the one thing here worth raising the
	// level for: it means either the archive is damaged or this reader's
	// understanding of the layout has drifted from the writer's, and both are
	// worth someone's attention rather than a silently short answer.
	switch {
	case span.Overran:
		body += " -- WARNING: a record claimed payload bytes past the end of the file"
		rec.Priority = 4 // LOG_WARNING
	case span.Truncated:
		body += " -- stopped at the " + strconv.Itoa(maxAtopRecords) + "-sample cap"
	case span.Slack != 0:
		body += " -- WARNING: " + strconv.FormatInt(span.Slack, 10) +
			" bytes at the end were not accounted for by the sample chain"
		rec.Priority = 4 // LOG_WARNING
	}

	rec.Body = body
	return rec, true
}
