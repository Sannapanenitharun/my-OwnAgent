package logs

import (
	"bytes"
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
