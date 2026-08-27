package logs

import "testing"

func TestDecodeDockerLogUnwrapsTheMessage(t *testing.T) {
	line := `{"log":"level=INFO msg=\"server started\"\n","stream":"stdout","time":"2026-08-02T09:50:46.411Z"}`
	body, stream, ok := decodeDockerLog(line)
	if !ok {
		t.Fatal("a docker json-file line was not recognised")
	}
	if body != `level=INFO msg="server started"` {
		t.Errorf("body = %q; the trailing newline must go and the message must be unwrapped", body)
	}
	if stream != "stdout" {
		t.Errorf("stream = %q", stream)
	}
}

func TestDecodeDockerLogLeavesOrdinaryLinesAlone(t *testing.T) {
	// Most log lines are not JSON, and a few are JSON that is not Docker's.
	// Neither may be rewritten.
	for _, line := range []string{
		"Aug 27 09:04:11 host sshd[123]: Accepted publickey for ubuntu",
		`{"level":"info","msg":"an application that logs JSON itself"}`,
		"",
		"{",
		`{"log":}`,
	} {
		if _, _, ok := decodeDockerLog(line); ok {
			t.Errorf("line was wrongly decoded as a docker envelope: %q", line)
		}
	}
}

func TestDecodeDockerLogKeepsStderrAsAnAttributeNotAnError(t *testing.T) {
	// Plenty of programs write ordinary output to stderr; the decoder reports
	// the stream and refuses to editorialise about severity.
	_, stream, ok := decodeDockerLog(`{"log":"starting\n","stream":"stderr","time":"2026-08-02T09:50:46Z"}`)
	if !ok || stream != "stderr" {
		t.Fatalf("ok=%v stream=%q", ok, stream)
	}
}

func TestDockerContainerIDFromPath(t *testing.T) {
	id := "197a675287225cafa1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381"
	got := dockerContainerID("/var/lib/docker/containers/" + id + "/" + id + "-json.log")
	if got != id {
		t.Errorf("id = %q, want %q", got, id)
	}
	for _, path := range []string{
		"/var/log/syslog",
		"/var/lib/docker/containers/short/short-json.log",
		"/var/log/not-a-container-json.log",
		"",
	} {
		if got := dockerContainerID(path); got != "" {
			t.Errorf("path %q yielded id %q, want none", path, got)
		}
	}
}
