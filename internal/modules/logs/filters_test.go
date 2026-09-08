package logs

import "testing"

// TestIncludeAndExcludeMatch. Until now the only filter was a global
// substring exclude, which cannot express "keep only the lines I care about"
// -- the case that actually reduces volume on a noisy host.
func TestIncludeAndExcludeMatch(t *testing.T) {
	const line = "2026-09-07 14:26:25 ERROR payment failed for order 91"

	if !matchesInclude(line, "") {
		t.Error("an empty include pattern must keep everything, or setting one filter turns the other on")
	}
	if matchesExclude(line, "") {
		t.Error("an empty exclude pattern must drop nothing")
	}
	if !matchesInclude(line, `\bERROR\b`) {
		t.Error("include pattern did not match a line it should keep")
	}
	if matchesInclude(line, `\bDEBUG\b`) {
		t.Error("include pattern matched a line it should have dropped")
	}
	if !matchesExclude(line, "payment failed") {
		t.Error("exclude pattern did not match")
	}

	// Unlike the multiline pattern, these are NOT anchored: an operator
	// filtering for "ERROR" means anywhere in the line, and forcing them to
	// write .* first would be a trap.
	if !matchesInclude(line, "order 91") {
		t.Error("include must match mid-line, not only at the start")
	}
}

// TestABrokenPatternFailsOpen. A regex that will not compile is rejected at
// config load; if one reaches the filter anyway, dropping every line would
// lose data that cannot be recovered, so the line passes.
func TestABrokenPatternFailsOpen(t *testing.T) {
	const bad = "([unclosed"
	if !matchesInclude("anything", bad) {
		t.Error("a broken include pattern dropped the line instead of failing open")
	}
	if matchesExclude("anything", bad) {
		t.Error("a broken exclude pattern dropped the line")
	}
}

func TestFilterSettingsParseAndValidate(t *testing.T) {
	s, err := ParseSettings(mustMC(t, map[string]string{
		"include.match": `\bERROR\b`,
		"exclude.match": "healthcheck",
	}))
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	if s.IncludeMatch != `\bERROR\b` || s.ExcludeMatch != "healthcheck" {
		t.Errorf("parsed %q / %q", s.IncludeMatch, s.ExcludeMatch)
	}

	// A pattern that cannot compile must fail at load, where somebody is
	// watching, rather than silently matching nothing for the next month.
	for _, key := range []string{"include.match", "exclude.match", "multiline.pattern"} {
		if _, err := ParseSettings(mustMC(t, map[string]string{key: "([unclosed"})); err == nil {
			t.Errorf("%s accepted an uncompilable expression", key)
		}
	}
}

func TestMultilineSettingsParse(t *testing.T) {
	def, err := ParseSettings(mustMC(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if def.Multiline != MultilineAuto {
		t.Errorf("default multiline = %q, want auto", def.Multiline)
	}
	if def.MultilineTimeout != defaultMultilineTimeout {
		t.Errorf("default timeout = %v", def.MultilineTimeout)
	}
	if def.StartPosition != StartEnd {
		t.Errorf("default start_position = %q, want end", def.StartPosition)
	}
	if def.Encoding != EncodingAuto {
		t.Errorf("default encoding = %q, want auto", def.Encoding)
	}

	// The flush timeout must exceed the collection interval, or a record split
	// across a cycle boundary is flushed before the rest of it is ever read.
	if def.MultilineTimeout <= def.Interval {
		t.Errorf("multiline timeout %v is not longer than the interval %v; "+
			"records spanning a cycle would always be split",
			def.MultilineTimeout, def.Interval)
	}

	if _, err := ParseSettings(mustMC(t, map[string]string{"multiline": "yes"})); err == nil {
		t.Error("multiline accepted a value that is not off/auto/pattern")
	}
	if _, err := ParseSettings(mustMC(t, map[string]string{"multiline": "pattern"})); err == nil {
		t.Error("multiline=pattern was accepted with no pattern set")
	}
	if _, err := ParseSettings(mustMC(t, map[string]string{"start_position": "middle"})); err == nil {
		t.Error("start_position accepted an invalid value")
	}
	if _, err := ParseSettings(mustMC(t, map[string]string{"encoding": "ebcdic"})); err == nil {
		t.Error("encoding accepted an unsupported value")
	}

	ok, err := ParseSettings(mustMC(t, map[string]string{
		"multiline": "pattern", "multiline.pattern": `^\d{4}-\d{2}-\d{2}`,
		"start_position": "beginning", "encoding": "utf-16-le",
	}))
	if err != nil {
		t.Fatalf("valid settings rejected: %v", err)
	}
	if ok.Multiline != MultilinePattern || ok.StartPosition != StartBeginning || ok.Encoding != EncodingUTF16LE {
		t.Errorf("parsed %+v", ok)
	}
}
