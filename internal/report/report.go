// Package report renders an audit report as text, JSON or Markdown.
//
// Markdown exists because the report is a deliverable: it is pasted into the
// restore record for the engagement, next to the timestamp and the operator's
// name.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/moveeeax/terraform-aws-eth-validator/internal/audit"
)

// Format is an output renderer.
type Format string

const (
	Text     Format = "text"
	JSON     Format = "json"
	Markdown Format = "markdown"
)

// ParseFormat maps a CLI string onto a Format.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case Text:
		return Text, nil
	case JSON:
		return JSON, nil
	case Markdown:
		return Markdown, nil
	}
	return "", fmt.Errorf("unknown format %q (want text, json or markdown)", s)
}

// Write renders rep in the requested format. failOn is the threshold used for
// the pass/fail line so the rendered report matches the exit code.
func Write(w io.Writer, rep audit.Report, f Format, failOn audit.Severity) error {
	switch f {
	case JSON:
		return writeJSON(w, rep, failOn)
	case Markdown:
		return writeMarkdown(w, rep, failOn)
	default:
		return writeText(w, rep, failOn)
	}
}

type jsonEnvelope struct {
	audit.Report
	FailOn  audit.Severity `json:"fail_on"`
	Blocked bool           `json:"blocked"`
}

func writeJSON(w io.Writer, rep audit.Report, failOn audit.Severity) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonEnvelope{
		Report:  rep,
		FailOn:  failOn,
		Blocked: rep.CountAtOrAbove(failOn) > 0,
	})
}

func writeText(w io.Writer, rep audit.Report, failOn audit.Severity) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }

	p("slashguard — EIP-3076 slashing-protection preflight\n\n")
	p("  interchange   %s\n", rep.InterchangeFile)
	if rep.KeystoreDir != "" {
		p("  keystores     %s (%d key(s))\n", rep.KeystoreDir, rep.KeysOnDisk)
		p("  coverage      %d of %d local key(s) have a protection record\n", rep.KeysProtected, rep.KeysOnDisk)
	} else {
		p("  keystores     (not supplied)\n")
	}
	p("  keys exported %d\n", rep.KeysInExport)

	if len(rep.Findings) == 0 {
		p("\nNo findings.\n")
	} else {
		p("\n%d finding(s)\n", len(rep.Findings))
		for _, f := range rep.Findings {
			p("\n  [%s] %-8s %s\n", f.Rule, f.Severity, f.Title)
			if f.Subject != "" {
				p("    subject     %s\n", f.Subject)
			}
			p("    detail      %s\n", f.Detail)
			p("    failure     how this becomes a slashing:\n")
			for i, step := range f.Failure {
				p("                %d. %s\n", i+1, step)
			}
			p("    remediation %s\n", f.Remedy)
		}
	}

	if len(rep.Skipped) > 0 {
		p("\n%d check(s) skipped\n", len(rep.Skipped))
		for _, s := range rep.Skipped {
			p("  [%s] %s — %s\n", s.Rule, s.Title, s.Reason)
		}
	}

	blocking := rep.CountAtOrAbove(failOn)
	p("\n")
	if blocking > 0 {
		p("RESULT: DO NOT START THE VALIDATOR — %d finding(s) at or above %s\n", blocking, failOn)
	} else {
		p("RESULT: no finding at or above %s\n", failOn)
	}
	return nil
}

func writeMarkdown(w io.Writer, rep audit.Report, failOn audit.Severity) error {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }

	p("# Slashing-protection preflight\n\n")
	p("| | |\n|---|---|\n")
	p("| Interchange file | `%s` |\n", rep.InterchangeFile)
	if rep.KeystoreDir != "" {
		p("| Keystore directory | `%s` |\n", rep.KeystoreDir)
		p("| Keys on disk | %d |\n", rep.KeysOnDisk)
		p("| Keys with a protection record | %d |\n", rep.KeysProtected)
	}
	p("| Keys in export | %d |\n", rep.KeysInExport)
	blocking := rep.CountAtOrAbove(failOn)
	verdict := fmt.Sprintf("PASS at threshold `%s`", failOn)
	if blocking > 0 {
		verdict = fmt.Sprintf("**BLOCKED** — %d finding(s) at or above `%s`", blocking, failOn)
	}
	p("| Result | %s |\n", verdict)

	p("\n## Findings\n\n")
	if len(rep.Findings) == 0 {
		p("None.\n")
	}
	for _, f := range rep.Findings {
		p("### %s — %s (%s)\n\n", f.Rule, f.Title, f.Severity)
		if f.Subject != "" {
			p("**Subject:** `%s`\n\n", f.Subject)
		}
		p("%s\n\n", f.Detail)
		p("**Failure sequence**\n\n")
		for i, step := range f.Failure {
			p("%d. %s\n", i+1, step)
		}
		p("\n**Remediation:** %s\n\n", f.Remedy)
	}

	if len(rep.Skipped) > 0 {
		p("## Checks not run\n\n")
		for _, s := range rep.Skipped {
			p("- `%s` %s — %s\n", s.Rule, s.Title, s.Reason)
		}
		p("\n")
	}
	return nil
}
