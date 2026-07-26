package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/moveeeax/terraform-aws-eth-validator/internal/interchange"
	"github.com/moveeeax/terraform-aws-eth-validator/internal/keystore"
)

const (
	fixtures  = "../../testdata/interchange"
	keystores = "../../testdata/keystores"

	pubA = "0x23eb26705c28e246e8765718564e748ee0c2239a60a5451516ff712236fa5bb008a07d3318b60cfd0d60ba8c09dafb58"
	pubC = "0xdfbd85c4e86a4c99b58f44b2aad009e1af35888082e270dc6b5c0834e5445d3d11b7df5474c58c4997a5df323c9024eb"

	// The two fixture networks. These are fixture values, not real genesis
	// validators roots: the tool never hardcodes a network, the operator
	// supplies the root from their own beacon node.
	netOne = "0x415f7d28a5d66b012547d7991089127689f11afa0b6792a080a000a15bbd0352"
	netTwo = "0x1ba4fac80b91c138b971a9efcdeae14c50b30f549048883b54d2407056171565"
)

func load(t *testing.T, name string) *interchange.File {
	t.Helper()
	f, err := os.Open(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	doc, err := interchange.Parse(f)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return doc
}

func loadKeys(t *testing.T, dir string) *keystore.Set {
	t.Helper()
	set, err := keystore.Load(filepath.Join(keystores, dir))
	if err != nil {
		t.Fatalf("load keystores: %v", err)
	}
	return set
}

// rules returns the multiset of rule ids in a report.
func rules(rep Report) map[string]int {
	out := map[string]int{}
	for _, f := range rep.Findings {
		out[f.Rule]++
	}
	return out
}

func skippedRules(rep Report) map[string]bool {
	out := map[string]bool{}
	for _, s := range rep.Skipped {
		out[s.Rule] = true
	}
	return out
}

func mustHave(t *testing.T, rep Report, rule string, want int) {
	t.Helper()
	if got := rules(rep)[rule]; got != want {
		t.Errorf("%s findings = %d, want %d (all findings: %v)", rule, got, want, rules(rep))
	}
}

func opts(root string, epoch int64, lag uint64) Options {
	o := Options{GenesisValidatorsRoot: root, MaxEpochLag: lag}
	if epoch >= 0 {
		o.CurrentEpoch, o.HaveCurrentEpoch = uint64(epoch), true
	}
	return o
}

func TestCleanExportProducesNoFindings(t *testing.T) {
	rep := Run(load(t, "clean.json"), loadKeys(t, "clean"), opts(netOne, 120004, 4))
	if len(rep.Findings) != 0 {
		t.Fatalf("expected a clean run, got %+v", rep.Findings)
	}
	if len(rep.Skipped) != 0 {
		t.Errorf("expected no skipped checks, got %+v", rep.Skipped)
	}
	if rep.KeysOnDisk != 2 || rep.KeysProtected != 2 || rep.KeysInExport != 2 {
		t.Errorf("coverage = %d/%d on disk, %d exported; want 2/2 and 2",
			rep.KeysProtected, rep.KeysOnDisk, rep.KeysInExport)
	}
	if rep.Worst() != Info {
		t.Errorf("worst severity = %s, want info", rep.Worst())
	}
}

func TestWrongNetworkIsCritical(t *testing.T) {
	rep := Run(load(t, "wrong-network.json"), loadKeys(t, "clean"), opts(netOne, 120004, 4))
	mustHave(t, rep, "SP002", 1)
	if rep.Worst() != Critical {
		t.Errorf("worst = %s, want critical", rep.Worst())
	}
	if rep.Findings[0].Rule != "SP002" {
		t.Errorf("critical finding should sort first, got %s", rep.Findings[0].Rule)
	}
}

func TestNetworkCheckSkippedWhenRootNotSupplied(t *testing.T) {
	rep := Run(load(t, "wrong-network.json"), loadKeys(t, "clean"), opts("", 120004, 4))
	mustHave(t, rep, "SP002", 0)
	if !skippedRules(rep)["SP002"] {
		t.Errorf("SP002 should be reported as skipped, got %+v", rep.Skipped)
	}
}

func TestMissingGenesisRootIsAFinding(t *testing.T) {
	rep := Run(load(t, "no-genesis-root.json"), loadKeys(t, "clean"), opts(netOne, 120004, 4))
	mustHave(t, rep, "SP003", 1)
	// SP002 cannot be decided once the root is unusable, and must not be
	// silently reported as passing.
	mustHave(t, rep, "SP002", 0)
}

func TestBadFormatVersion(t *testing.T) {
	rep := Run(load(t, "bad-version.json"), nil, opts(netOne, -1, 4))
	mustHave(t, rep, "SP001", 1)
	if rep.Findings[0].Severity != Critical {
		t.Errorf("SP001 severity = %s, want critical", rep.Findings[0].Severity)
	}
}

func TestDuplicatePubkey(t *testing.T) {
	rep := Run(load(t, "duplicate-pubkey.json"), loadKeys(t, "clean"), opts(netOne, 120004, 4))
	mustHave(t, rep, "SP005", 1)
	if rep.KeysInExport != 2 {
		t.Errorf("keys in export = %d, want 2 distinct keys from 3 records", rep.KeysInExport)
	}
	for _, f := range rep.Findings {
		if f.Rule == "SP005" && f.Subject != pubA {
			t.Errorf("SP005 subject = %s, want %s", f.Subject, pubA)
		}
	}
}

func TestInvertedAttestationEpochs(t *testing.T) {
	rep := Run(load(t, "inverted-epochs.json"), loadKeys(t, "clean"), opts(netOne, 120004, 4))
	mustHave(t, rep, "SP007", 1)
}

func TestEmptyHistory(t *testing.T) {
	rep := Run(load(t, "empty-history.json"), loadKeys(t, "clean"), opts(netOne, 120004, 4))
	mustHave(t, rep, "SP006", 1)
	for _, f := range rep.Findings {
		if f.Rule == "SP006" && f.Subject != pubA {
			t.Errorf("SP006 subject = %s, want %s", f.Subject, pubA)
		}
	}
}

func TestStaleExport(t *testing.T) {
	rep := Run(load(t, "stale.json"), loadKeys(t, "clean"), opts(netOne, 120004, 4))
	mustHave(t, rep, "SP008", 1)

	// The same file is fine when head has not moved past the tolerance.
	rep = Run(load(t, "stale.json"), loadKeys(t, "clean"), opts(netOne, 110003, 4))
	mustHave(t, rep, "SP008", 0)
}

func TestStalenessSkippedWithoutCurrentEpoch(t *testing.T) {
	rep := Run(load(t, "stale.json"), loadKeys(t, "clean"), opts(netOne, -1, 4))
	mustHave(t, rep, "SP008", 0)
	if !skippedRules(rep)["SP008"] {
		t.Errorf("SP008 should be skipped without --current-epoch, got %+v", rep.Skipped)
	}
}

func TestEpochsInTheFuture(t *testing.T) {
	rep := Run(load(t, "clean.json"), loadKeys(t, "clean"), opts(netOne, 100, 4))
	mustHave(t, rep, "SP012", 1)
	mustHave(t, rep, "SP008", 0)
}

func TestUncoveredKeystoreIsCritical(t *testing.T) {
	rep := Run(load(t, "clean.json"), loadKeys(t, "extra"), opts(netOne, 120004, 4))
	mustHave(t, rep, "SP004", 1)
	// notes.json in that directory is unreadable as a keystore.
	mustHave(t, rep, "SP014", 1)
	if rep.KeysProtected != 2 || rep.KeysOnDisk != 3 {
		t.Errorf("coverage = %d/%d, want 2/3", rep.KeysProtected, rep.KeysOnDisk)
	}
	for _, f := range rep.Findings {
		if f.Rule == "SP004" && f.Subject != pubC {
			t.Errorf("SP004 subject = %s, want %s", f.Subject, pubC)
		}
	}
}

func TestExportCoversKeyNotOnDisk(t *testing.T) {
	// The "extra" export covers three keys; this host holds two of them.
	rep := Run(load(t, "clean.json"), loadKeys(t, "clean"), opts(netOne, 120004, 4))
	mustHave(t, rep, "SP009", 0)

	trimmed := load(t, "clean.json")
	trimmed.Data = trimmed.Data[:1]
	rep = Run(trimmed, loadKeys(t, "clean"), opts(netOne, 120004, 4))
	mustHave(t, rep, "SP004", 1)
	mustHave(t, rep, "SP009", 0)
}

func TestCoverageSkippedWithoutKeystores(t *testing.T) {
	rep := Run(load(t, "clean.json"), nil, opts(netOne, 120004, 4))
	sk := skippedRules(rep)
	if !sk["SP004"] || !sk["SP009"] {
		t.Errorf("SP004 and SP009 should both be skipped, got %+v", rep.Skipped)
	}
}

func TestMalformedValues(t *testing.T) {
	rep := Run(load(t, "malformed.json"), nil, opts(netOne, -1, 4))
	mustHave(t, rep, "SP010", 2) // one bad slot, one bad target epoch
	mustHave(t, rep, "SP011", 1) // 0xdeadbeef is not a BLS pubkey
	mustHave(t, rep, "SP013", 1) // three JSON-number fields, reported once
	// The malformed-pubkey record also has no history, but an unmatchable
	// pubkey is the more actionable finding and empty history is not
	// double-reported for it.
	mustHave(t, rep, "SP006", 0)
}

func TestFindingsAlwaysCarryAFailureSequence(t *testing.T) {
	for _, name := range []string{
		"wrong-network.json", "bad-version.json", "duplicate-pubkey.json",
		"inverted-epochs.json", "empty-history.json", "stale.json",
		"malformed.json", "no-genesis-root.json",
	} {
		rep := Run(load(t, name), loadKeys(t, "extra"), opts(netOne, 120004, 4))
		if len(rep.Findings) == 0 {
			t.Errorf("%s: expected findings", name)
		}
		for _, f := range rep.Findings {
			if len(f.Failure) < 2 {
				t.Errorf("%s: %s has %d failure step(s); a finding without a failure sequence is a lint warning",
					name, f.Rule, len(f.Failure))
			}
			if f.Remedy == "" {
				t.Errorf("%s: %s has no remediation", name, f.Rule)
			}
			if f.Detail == "" {
				t.Errorf("%s: %s has no detail", name, f.Rule)
			}
		}
	}
}

func TestFindingsSortWorstFirst(t *testing.T) {
	rep := Run(load(t, "malformed.json"), loadKeys(t, "extra"), opts(netTwo, 120004, 4))
	if len(rep.Findings) < 3 {
		t.Fatalf("expected several findings, got %d", len(rep.Findings))
	}
	for i := 1; i < len(rep.Findings); i++ {
		prev, cur := rep.Findings[i-1], rep.Findings[i]
		if prev.Severity.Rank() < cur.Severity.Rank() {
			t.Fatalf("findings out of order at %d: %s before %s", i, prev.Severity, cur.Severity)
		}
		if prev.Severity == cur.Severity && prev.Rule > cur.Rule {
			t.Fatalf("equal severities not ordered by rule at %d: %s before %s", i, prev.Rule, cur.Rule)
		}
	}
}

func TestCountAtOrAbove(t *testing.T) {
	rep := Run(load(t, "malformed.json"), nil, opts(netOne, -1, 4))
	if got := rep.CountAtOrAbove(Critical); got != 2 {
		t.Errorf("critical count = %d, want 2", got)
	}
	if rep.CountAtOrAbove(Info) != len(rep.Findings) {
		t.Errorf("info count = %d, want %d", rep.CountAtOrAbove(Info), len(rep.Findings))
	}
	if rep.CountAtOrAbove(High) < rep.CountAtOrAbove(Critical) {
		t.Error("high count must include critical findings")
	}
}

func TestParseSeverity(t *testing.T) {
	for _, s := range []string{"info", "MEDIUM", " high ", "critical"} {
		if _, err := ParseSeverity(s); err != nil {
			t.Errorf("ParseSeverity(%q) failed: %v", s, err)
		}
	}
	if _, err := ParseSeverity("catastrophic"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
}
