package logs

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// utf16File writes text as UTF-16 with a byte-order mark, the way Windows
// tooling and several Java loggers do.
func utf16File(t *testing.T, dir, name, text string, bigEndian bool) string {
	t.Helper()
	var b []byte
	if bigEndian {
		b = append(b, 0xFE, 0xFF)
	} else {
		b = append(b, 0xFF, 0xFE)
	}
	for _, r := range text {
		var u [2]byte
		if bigEndian {
			binary.BigEndian.PutUint16(u[:], uint16(r))
		} else {
			binary.LittleEndian.PutUint16(u[:], uint16(r))
		}
		b = append(b, u[0], u[1])
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestUTF16TextIsNotMistakenForBinary is the regression this whole path
// exists for.
//
// The binary guard rejects any file containing a NUL byte, which is right for
// wtmp and catastrophic for UTF-16: ASCII encoded as UTF-16 is half NUL bytes,
// so a perfectly good log file was not mis-parsed, it was dropped entirely and
// silently. Datadog supports these files explicitly; we were losing them.
func TestUTF16TextIsNotMistakenForBinary(t *testing.T) {
	dir := t.TempDir()
	for _, be := range []bool{false, true} {
		name := "app-le.log"
		if be {
			name = "app-be.log"
		}
		path := utf16File(t, dir, name, "2026-09-07 14:26:25 hello\n", be)

		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		enc, bom := sniffEncoding(f, EncodingAuto)
		want := EncodingUTF16LE
		if be {
			want = EncodingUTF16BE
		}
		if enc != want || bom != 2 {
			t.Errorf("%s: sniffed %s bom=%d, want %s bom=2", name, enc, bom, want)
		}
		// The old behaviour, kept here so the reason is visible: the raw
		// bytes DO look binary, and that is exactly why the BOM has to be
		// consulted first.
		if !sniffBinary(f) {
			t.Errorf("%s: raw UTF-16 bytes no longer trip the NUL test; "+
				"this test is no longer proving anything", name)
		}
		f.Close()
	}
}

// TestUTF16FileIsTailedAsText drives the real tailer end to end.
func TestUTF16FileIsTailedAsText(t *testing.T) {
	dir := t.TempDir()
	path := utf16File(t, dir, "app.log",
		"2026-09-07 14:26:25 first\n2026-09-07 14:26:26 second\n", false)

	s := DefaultSettings()
	s.Paths = []string{path}
	s.StartPosition = StartBeginning
	s.Multiline = MultilineOff

	tl := newFileTailer()
	got, err := tl.Read(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d records, want 2: %+v", len(got), got)
	}
	if got[0].Body != "2026-09-07 14:26:25 first" {
		t.Errorf("first line = %q", got[0].Body)
	}
	if strings.ContainsRune(got[0].Body+got[1].Body, 0) {
		t.Error("a NUL survived decoding -- the bytes were passed through undecoded")
	}
	if strings.ContainsRune(got[0].Body, '\uFEFF') {
		t.Error("the byte-order mark was delivered as content")
	}
}

// TestUTF16PartialLineIsNotEmittedEarly. The file is appended to while the
// tailer runs, so a read that ends mid-line must wait rather than deliver half
// a line that will be delivered again in full.
func TestUTF16PartialLineIsNotEmittedEarly(t *testing.T) {
	le := func(text string) []byte {
		b := []byte{0xFF, 0xFE}
		for _, r := range text {
			var u [2]byte
			binary.LittleEndian.PutUint16(u[:], uint16(r))
			b = append(b, u[0], u[1])
		}
		return b
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "growing.log")
	if err := os.WriteFile(path, le("2026-09-07 14:26:25 complete\n2026-09-07 14:26:26 incom"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := DefaultSettings()
	s.Paths = []string{path}
	s.StartPosition = StartBeginning
	s.Multiline = MultilineOff

	tl := newFileTailer()
	got, _ := tl.Read(context.Background(), s)
	if len(got) != 1 {
		t.Fatalf("read %d records, want only the complete line: %+v", len(got), got)
	}

	// Finish the line; the next read must deliver it whole and exactly once.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	rest := le("plete\n")[2:] // no second BOM
	if _, err := f.Write(rest); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got2, _ := tl.Read(context.Background(), s)
	if len(got2) != 1 {
		t.Fatalf("second read returned %d records, want 1: %+v", len(got2), got2)
	}
	if got2[0].Body != "2026-09-07 14:26:26 incomplete" {
		t.Errorf("line = %q, want the reassembled whole line", got2[0].Body)
	}
}

// TestAnOddTrailingByteDoesNotDesynchronise. UTF-16 advances two bytes at a
// time; an offset landing mid-unit turns every later read into mojibake that
// still looks like text, which is the worst kind of wrong.
func TestAnOddTrailingByteDoesNotDesynchronise(t *testing.T) {
	text, consumed := decodeUTF16Lines([]byte{'h', 0, 'i', 0, '\n', 0, 'x'}, false)
	if text != "hi\n" {
		t.Errorf("text = %q, want %q", text, "hi\n")
	}
	if consumed != 6 {
		t.Errorf("consumed = %d, want 6 -- the stray byte must be left for next time", consumed)
	}
	if _, c := decodeUTF16Lines([]byte{'h', 0, 'i', 0}, false); c != 0 {
		t.Errorf("consumed = %d on a buffer with no newline, want 0", c)
	}
}

// TestUTF8BOMIsSkipped. A leading U+FEFF renders as a stray glyph and breaks
// any parser that expects the line to start with a timestamp.
func TestUTF8BOMIsSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bom.log")
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte("2026-09-07 14:26:25 hello\n")...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	s := DefaultSettings()
	s.Paths = []string{path}
	s.StartPosition = StartBeginning
	s.Multiline = MultilineOff

	tl := newFileTailer()
	got, _ := tl.Read(context.Background(), s)
	if len(got) != 1 {
		t.Fatalf("read %d records, want 1", len(got))
	}
	if strings.ContainsRune(got[0].Body, '\uFEFF') || got[0].Body[0] != '2' {
		t.Errorf("line = %q, want it to begin at the timestamp", got[0].Body)
	}
}

// TestExplicitEncodingOverridesTheAbsenceOfABOM is how a UTF-16 file with no
// mark is read at all -- the same requirement Datadog places on its users.
func TestExplicitEncodingOverridesTheAbsenceOfABOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nobom.log")
	var b []byte
	for _, r := range "2026-09-07 14:26:25 hello\n" {
		var u [2]byte
		binary.LittleEndian.PutUint16(u[:], uint16(r))
		b = append(b, u[0], u[1])
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}

	s := DefaultSettings()
	s.Paths = []string{path}
	s.StartPosition = StartBeginning
	s.Encoding = EncodingUTF16LE
	s.Multiline = MultilineOff

	tl := newFileTailer()
	got, _ := tl.Read(context.Background(), s)
	if len(got) != 1 || got[0].Body != "2026-09-07 14:26:25 hello" {
		t.Fatalf("got %+v, want the decoded line", got)
	}

	// Without the declaration the same file is refused, and that refusal is
	// correct: undeclared UTF-16 with no mark is indistinguishable from a
	// binary file.
	s2 := DefaultSettings()
	s2.Paths = []string{path}
	s2.StartPosition = StartBeginning
	tl2 := newFileTailer()
	if got2, _ := tl2.Read(context.Background(), s2); len(got2) != 0 {
		t.Errorf("undeclared UTF-16 without a BOM was read anyway: %+v", got2)
	}
}

// TestStartPositionEndSkipsHistory pins the default, which is the one that
// stops a restart from re-shipping a month of logs.
func TestStartPositionEndSkipsHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.log")
	if err := os.WriteFile(path, []byte("2026-09-07 14:26:25 history\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := DefaultSettings()
	s.Paths = []string{path}
	s.Multiline = MultilineOff

	tl := newFileTailer()
	if got, _ := tl.Read(context.Background(), s); len(got) != 0 {
		t.Fatalf("default start position shipped %d historical records", len(got))
	}

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("2026-09-07 14:26:26 new\n")
	f.Close()

	got, _ := tl.Read(context.Background(), s)
	if len(got) != 1 || !strings.Contains(got[0].Body, "new") {
		t.Errorf("got %+v, want only the appended line", got)
	}
}

// TestStartPositionBeginningReadsOnTheFirstCycle. Making the operator wait an
// interval for history they explicitly asked for serves nobody.
func TestStartPositionBeginningReadsOnTheFirstCycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.log")
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := DefaultSettings()
	s.Paths = []string{path}
	s.StartPosition = StartBeginning
	s.Multiline = MultilineOff

	tl := newFileTailer()
	got, _ := tl.Read(context.Background(), s)
	if len(got) != 3 {
		t.Fatalf("first cycle read %d records, want 3", len(got))
	}
	// And it must not re-read them.
	if again, _ := tl.Read(context.Background(), s); len(again) != 0 {
		t.Errorf("second cycle re-read %d records", len(again))
	}
}
