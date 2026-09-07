//go:build linux

package logs

import (
	"context"
	"io"
	"os"
	"sort"
	"strconv"
	"time"
)

// lastlogTailer reports the last-login table.
//
// IT DELIBERATELY BREAKS THE CONVENTION every other reader here follows.
// The file tailer, the journal reader and the utmp reader all start at the
// current end of their input so that a restart does not re-ship history. This
// one emits its whole populated contents on the first read.
//
// The convention does not apply because /var/log/lastlog has no end. It is a
// table written in place, not a stream appended to, and its current contents
// are a statement about the present: these are the accounts that have been
// used, and this is when. A reader that started "at the end" would emit
// nothing until somebody logged in again -- which on a host whose whole
// security question is "has anyone touched the dormant accounts" means
// emitting nothing, ever, right up until the moment it is too late.
//
// The baseline is bounded twice: by bytes read from a sparse file that can be
// nominally enormous, and by accounts emitted in one cycle. See
// maxLastlogBytes and maxLastlogAccounts.
type lastlogTailer struct {
	// seen maps UID to the last-login second already reported. A UID present
	// here with an equal timestamp is not re-emitted; a changed timestamp is
	// a new login and is.
	seen   map[int]int64
	seeded bool

	// users caches /etc/passwd, refreshed when the file's mtime moves rather
	// than on a timer: accounts change when someone changes them, and re-
	// parsing the file every two seconds would pay for a lookup that is
	// identical almost every time.
	users     map[int]string
	usersMod  time.Time
	usersSize int64
}

func newLastlogTailer() *lastlogTailer {
	return &lastlogTailer{seen: map[int]int64{}, users: map[int]string{}}
}

func defaultLastlogFile() string { return "/var/log/lastlog" }

func defaultPasswdFile() string { return "/etc/passwd" }

func (t *lastlogTailer) Read(_ context.Context, s Settings) ([]Record, error) {
	path := s.LastlogFile
	if path == "" {
		path = defaultLastlogFile()
	}
	t.refreshUsers()

	records, truncated := t.scan(path)
	budget := s.MaxBatch
	if budget > maxLastlogAccounts {
		budget = maxLastlogAccounts
	}

	// Sort by UID so a budget truncation cuts the same place twice, rather
	// than shipping a different arbitrary subset of accounts each cycle.
	sort.Slice(records, func(i, j int) bool { return records[i].UID < records[j].UID })

	out := make([]Record, 0, 8)
	for _, r := range records {
		unix := r.When.Unix()
		if prev, ok := t.seen[r.UID]; ok && prev == unix {
			continue
		}
		if len(out) >= budget {
			// Stop BEFORE recording this UID as seen. Marking it and then
			// breaking would drop the account permanently: the next cycle
			// would find the timestamp unchanged and skip it forever.
			break
		}
		t.seen[r.UID] = unix
		r.User = t.users[r.UID]
		if msg := lastlogMessage(r); msg != "" {
			out = append(out, Record{
				Body:   msg,
				Source: SourceLastlog,
				File:   path,
				// A dormant account that suddenly has a login is the signal
				// this source exists for, but the table cannot say whether an
				// entry is new or merely newly observed. Info is the honest
				// level; alerting belongs on the wtmp/btmp events, which do
				// carry that distinction.
				Priority:    6, // LOG_INFO
				HasPriority: true,
			})
		}
	}

	if truncated && !t.seeded {
		out = append(out, Record{
			Body: "lastlog is larger than " + strconv.Itoa(maxLastlogBytes) +
				" bytes and was read only that far; accounts with higher UIDs are not reported",
			Source:      SourceLastlog,
			File:        path,
			Priority:    4, // LOG_WARNING -- a silent partial read would be worse
			HasPriority: true,
		})
	}
	t.seeded = true
	return out, nil
}

// scan reads the table, bounded. It reports whether the file was longer than
// the cap, which is a fact the caller must not swallow.
func (t *lastlogTailer) scan(path string) ([]lastlogRecord, bool) {
	f, err := os.Open(path)
	if err != nil {
		// 0644 root:utmp on Ubuntu, so this usually succeeds; when it does
		// not, denial is a privilege boundary rather than a fault.
		return nil, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return nil, false
	}

	limit := st.Size()
	truncated := false
	if limit > maxLastlogBytes {
		limit, truncated = maxLastlogBytes, true
	}

	// A whole number of records per read, so no record ever straddles two
	// buffers and needs stitching.
	const blockRecords = 512
	buf := make([]byte, blockRecords*lastlogRecordLen)

	var out []lastlogRecord
	var off int64
	for off < limit {
		want := limit - off
		if want > int64(len(buf)) {
			want = int64(len(buf))
		}
		n, rerr := f.ReadAt(buf[:want], off)
		if n > 0 {
			out = append(out, lastlogRecords(buf[:n], int(off/lastlogRecordLen))...)
		}
		if rerr != nil {
			// io.EOF at the tail is the normal end of a short final block.
			if rerr != io.EOF {
				return out, truncated
			}
			break
		}
		off += int64(n)
	}
	return out, truncated
}

// refreshUsers re-reads /etc/passwd only when it has actually changed.
func (t *lastlogTailer) refreshUsers() {
	st, err := os.Stat(defaultPasswdFile())
	if err != nil {
		return
	}
	if st.ModTime().Equal(t.usersMod) && st.Size() == t.usersSize {
		return
	}
	content, err := os.ReadFile(defaultPasswdFile())
	if err != nil {
		return
	}
	t.users = parsePasswdUIDs(content)
	t.usersMod, t.usersSize = st.ModTime(), st.Size()
}
