package logs

import (
	"bytes"
	"encoding/json"
	"strings"
)

var messageKey = []byte("MESSAGE=")

func extractJournalMessages(buf []byte, max int) []Record {
	var out []Record
	for len(buf) > 0 && (max <= 0 || len(out) < max) {
		i := bytes.Index(buf, messageKey)
		if i < 0 {
			break
		}
		if i > 0 && buf[i-1] != 0 && buf[i-1] != '\n' {
			buf = buf[i+1:]
			continue
		}
		rest := buf[i+len(messageKey):]
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			end = bytes.IndexByte(rest, '\n')
		}
		if end < 0 {
			break
		}
		msg := strings.TrimRight(string(rest[:end]), "\r")
		if msg != "" {
			out = append(out, Record{Body: msg, Source: SourceJournald})
		}
		buf = rest[end+1:]
	}
	return out
}

// Docker's json-file driver wraps every container line in an envelope:
//
//	{"log":"the actual line\n","stream":"stdout","time":"2026-08-02T09:50:46Z"}
//
// Shipping that verbatim buries the message inside JSON and makes a container's
// logs unreadable in any viewer. Decoding is by content, not configuration: a
// line either is such an envelope or it is not.
//
// stream is carried as an attribute rather than mapped to a severity. Plenty of
// programs write ordinary progress output to stderr, so treating stderr as an
// error would manufacture alarm the log itself never expressed.
func decodeDockerLog(line string) (body, stream string, ok bool) {
	if len(line) == 0 || line[0] != '{' || !strings.Contains(line, `"log"`) {
		return "", "", false
	}
	var env struct {
		Log    string `json:"log"`
		Stream string `json:"stream"`
	}
	if err := json.Unmarshal([]byte(line), &env); err != nil {
		return "", "", false
	}
	if env.Log == "" && env.Stream == "" {
		return "", "", false
	}
	return strings.TrimRight(env.Log, "\r\n"), env.Stream, true
}

// dockerContainerID recovers the container ID from a json-file path, which
// Docker names /var/lib/docker/containers/<id>/<id>-json.log. Without it a
// container's lines are attributed only to a path no operator recognises.
func dockerContainerID(path string) string {
	if !strings.HasSuffix(path, "-json.log") {
		return ""
	}
	base := path[strings.LastIndexAny(path, `/\`)+1:]
	id := strings.TrimSuffix(base, "-json.log")
	if len(id) < 12 {
		return ""
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return id
}

// containsAny reports whether line contains any of the substrings. An empty
// list matches nothing, so the filter is inert until configured.
func containsAny(line string, subs []string) bool {
	for _, s := range subs {
		if s != "" && strings.Contains(line, s) {
			return true
		}
	}
	return false
}
