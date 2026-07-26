package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestCleanRunExitsZero(t *testing.T) {
	code, out, errOut := exec(t,
		"--interchange", "../../testdata/interchange/clean.json",
		"--keystores", "../../testdata/keystores/clean",
		"--genesis-validators-root", netOne,
		"--current-epoch", "120004",
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "No findings.") {
		t.Errorf("stdout should report a clean run:\n%s", out)
	}
}

func TestUncoveredKeyBlocksTheStart(t *testing.T) {
	code, out, _ := exec(t,
		"--interchange", "../../testdata/interchange/clean.json",
		"--keystores", "../../testdata/keystores/extra",
		"--genesis-validators-root", netOne,
		"--current-epoch", "120004",
	)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "SP004") || !strings.Contains(out, "DO NOT START THE VALIDATOR") {
		t.Errorf("expected a blocking SP004 finding:\n%s", out)
	}
}

func TestWrongNetworkBlocksTheStart(t *testing.T) {
	code, out, _ := exec(t,
		"--interchange", "../../testdata/interchange/wrong-network.json",
		"--keystores", "../../testdata/keystores/clean",
		"--genesis-validators-root", netOne,
	)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "SP002") {
		t.Errorf("expected SP002:\n%s", out)
	}
}

func TestSkippedChecksAreVisibleOnAPass(t *testing.T) {
	// No keystore directory and no epoch: the run passes, but it must say
	// which checks did not run.
	code, out, _ := exec(t, "--interchange", "../../testdata/interchange/clean.json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	for _, rule := range []string{"SP002", "SP004", "SP008", "SP009"} {
		if !strings.Contains(out, rule) {
			t.Errorf("skipped rule %s not reported:\n%s", rule, out)
		}
	}
}

func TestFailOnLowersTheThreshold(t *testing.T) {
	// This export covers a third key that is not on this host: SP009, medium.
	// Nothing else fires, so the exit code moves purely with the threshold.
	args := []string{
		"--interchange", "../../testdata/interchange/extra-key-in-export.json",
		"--keystores", "../../testdata/keystores/clean",
		"--genesis-validators-root", netOne,
		"--current-epoch", "120004",
	}
	code, out, _ := exec(t, args...)
	if code != 0 {
		t.Fatalf("exit = %d at the default threshold, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "SP009") {
		t.Fatalf("expected an SP009 finding to be reported even though it does not block:\n%s", out)
	}

	code, out, _ = exec(t, append(args, "--fail-on", "medium")...)
	if code != 1 {
		t.Fatalf("exit = %d at --fail-on=medium, want 1\n%s", code, out)
	}
}

func TestJSONOutputParses(t *testing.T) {
	code, out, _ := exec(t,
		"--interchange", "../../testdata/interchange/duplicate-pubkey.json",
		"--keystores", "../../testdata/keystores/clean",
		"--format", "json",
	)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var doc struct {
		Blocked  bool `json:"blocked"`
		Findings []struct {
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out)
	}
	if !doc.Blocked {
		t.Error("blocked should be true")
	}
	found := false
	for _, f := range doc.Findings {
		if f.Rule == "SP005" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SP005 in %s", out)
	}
}

func TestMissingInterchangeFlagIsAUsageError(t *testing.T) {
	code, _, errOut := exec(t)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "--interchange is required") {
		t.Errorf("stderr should explain the missing flag:\n%s", errOut)
	}
}

func TestUnreadableFileIsExitTwo(t *testing.T) {
	code, _, errOut := exec(t, "--interchange", "../../testdata/interchange/nope.json")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if errOut == "" {
		t.Error("expected an error on stderr")
	}
}

func TestBadFlagValuesAreExitTwo(t *testing.T) {
	for _, args := range [][]string{
		{"--interchange", "../../testdata/interchange/clean.json", "--format", "sarif"},
		{"--interchange", "../../testdata/interchange/clean.json", "--fail-on", "catastrophic"},
		{"--interchange", "../../testdata/interchange/clean.json", "--keystores", "/no/such/dir"},
	} {
		if code, _, _ := exec(t, args...); code != 2 {
			t.Errorf("%v: exit = %d, want 2", args, code)
		}
	}
}

func TestVersionFlag(t *testing.T) {
	code, out, _ := exec(t, "--version")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.HasPrefix(out, "slashguard ") {
		t.Errorf("version output = %q", out)
	}
}

const netOne = "0x415f7d28a5d66b012547d7991089127689f11afa0b6792a080a000a15bbd0352"
