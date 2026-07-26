package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moveeeax/terraform-aws-eth-validator/internal/audit"
)

func sample() audit.Report {
	return audit.Report{
		InterchangeFile: "export.json",
		KeystoreDir:     "/var/lib/validator/keys",
		FormatVersion:   "5",
		KeysOnDisk:      3,
		KeysInExport:    2,
		KeysProtected:   2,
		Findings: []audit.Finding{{
			Rule:     "SP004",
			Severity: audit.Critical,
			Title:    "keystore on this host has no slashing-protection record",
			Subject:  "0xabc",
			Detail:   "keystore-2.json is present but absent from the export.",
			Failure:  []string{"first step", "second step"},
			Remedy:   "do not start the validator client",
		}},
		Skipped: []audit.Skipped{{
			Rule:   "SP008",
			Title:  "export is recent enough to be trusted",
			Reason: "--current-epoch was not supplied",
		}},
	}
}

func render(t *testing.T, rep audit.Report, f Format, failOn audit.Severity) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, rep, f, failOn); err != nil {
		t.Fatalf("write %s: %v", f, err)
	}
	return buf.String()
}

func TestTextIncludesFailureSequenceAndVerdict(t *testing.T) {
	out := render(t, sample(), Text, audit.High)
	for _, want := range []string{
		"SP004", "critical", "0xabc", "1. first step", "2. second step",
		"do not start the validator client",
		"1 check(s) skipped", "SP008",
		"RESULT: DO NOT START THE VALIDATOR",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n---\n%s", want, out)
		}
	}
}

func TestTextPassVerdictRespectsThreshold(t *testing.T) {
	rep := sample()
	rep.Findings[0].Severity = audit.Medium
	out := render(t, rep, Text, audit.High)
	if strings.Contains(out, "DO NOT START") {
		t.Errorf("a medium finding must not block at --fail-on=high\n---\n%s", out)
	}
	if !strings.Contains(out, "RESULT: no finding at or above high") {
		t.Errorf("missing pass verdict\n---\n%s", out)
	}
}

func TestTextHandlesEmptyReport(t *testing.T) {
	rep := audit.Report{InterchangeFile: "export.json", Findings: []audit.Finding{}}
	out := render(t, rep, Text, audit.High)
	if !strings.Contains(out, "No findings.") {
		t.Errorf("missing empty-report line\n---\n%s", out)
	}
	if !strings.Contains(out, "keystores     (not supplied)") {
		t.Errorf("an absent keystore directory should be stated explicitly\n---\n%s", out)
	}
}

func TestJSONIsMachineReadable(t *testing.T) {
	out := render(t, sample(), JSON, audit.High)
	var got struct {
		InterchangeFile string `json:"interchange_file"`
		KeysProtected   int    `json:"keys_protected"`
		FailOn          string `json:"fail_on"`
		Blocked         bool   `json:"blocked"`
		Findings        []struct {
			Rule     string   `json:"rule"`
			Severity string   `json:"severity"`
			Failure  []string `json:"failure_sequence"`
		} `json:"findings"`
		Skipped []struct {
			Rule string `json:"rule"`
		} `json:"skipped_checks"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if got.InterchangeFile != "export.json" || got.KeysProtected != 2 {
		t.Errorf("envelope fields wrong: %+v", got)
	}
	if got.FailOn != "high" || !got.Blocked {
		t.Errorf("fail_on = %q, blocked = %v; want high and true", got.FailOn, got.Blocked)
	}
	if len(got.Findings) != 1 || got.Findings[0].Rule != "SP004" || len(got.Findings[0].Failure) != 2 {
		t.Errorf("findings not carried through: %+v", got.Findings)
	}
	if len(got.Skipped) != 1 || got.Skipped[0].Rule != "SP008" {
		t.Errorf("skipped checks not carried through: %+v", got.Skipped)
	}
}

func TestJSONBlockedFollowsThreshold(t *testing.T) {
	rep := sample()
	rep.Findings[0].Severity = audit.Info
	out := render(t, rep, JSON, audit.Medium)
	var got struct {
		Blocked bool `json:"blocked"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Blocked {
		t.Error("an info finding must not block at --fail-on=medium")
	}
}

func TestMarkdownIsADeliverable(t *testing.T) {
	out := render(t, sample(), Markdown, audit.High)
	for _, want := range []string{
		"# Slashing-protection preflight",
		"| Keys with a protection record | 2 |",
		"**BLOCKED**",
		"### SP004 —",
		"**Failure sequence**",
		"1. first step",
		"## Checks not run",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q\n---\n%s", want, out)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{"text": Text, "JSON": JSON, " markdown ": Markdown} {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = (%v, %v), want %v", in, got, err, want)
		}
	}
	if _, err := ParseFormat("sarif"); err == nil {
		t.Error("expected an error for an unsupported format")
	}
}
