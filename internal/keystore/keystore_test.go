package keystore

import (
	"strings"
	"testing"
)

const (
	pubA = "0x23eb26705c28e246e8765718564e748ee0c2239a60a5451516ff712236fa5bb008a07d3318b60cfd0d60ba8c09dafb58"
	pubB = "0x40736adfe0bee6ac90bb96e9e44d15dace909941ac6f9ae8e0b84abb1ef7fac9154d506f52fde3f6922ef77e71638120"
	pubC = "0xdfbd85c4e86a4c99b58f44b2aad009e1af35888082e270dc6b5c0834e5445d3d11b7df5474c58c4997a5df323c9024eb"
)

func TestLoadIgnoresDepositData(t *testing.T) {
	set, err := Load("../../testdata/keystores/clean")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("keys = %d, want 2 (deposit_data must not be counted)", len(set.Keys))
	}
	for _, k := range set.Keys {
		if k.Pubkey == pubC {
			t.Errorf("%s came from deposit_data and must not be treated as a loadable key", pubC)
		}
	}
	if len(set.Skipped) != 0 {
		t.Errorf("skipped = %+v, want none", set.Skipped)
	}
}

func TestLoadNormalisesAndSorts(t *testing.T) {
	set, err := Load("../../testdata/keystores/extra")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []string{pubA, pubB, pubC}
	if len(set.Keys) != len(want) {
		t.Fatalf("keys = %d, want %d", len(set.Keys), len(want))
	}
	for i, w := range want {
		if set.Keys[i].Pubkey != w {
			t.Errorf("key[%d] = %s, want %s", i, set.Keys[i].Pubkey, w)
		}
		if !strings.HasPrefix(set.Keys[i].Pubkey, "0x") {
			t.Errorf("key[%d] is not 0x-prefixed", i)
		}
	}
}

func TestLoadReportsUnparseableFiles(t *testing.T) {
	set, err := Load("../../testdata/keystores/extra")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(set.Skipped) != 1 || set.Skipped[0].File != "notes.json" {
		t.Fatalf("skipped = %+v, want exactly notes.json", set.Skipped)
	}
}

func TestLoadMissingDirIsAnError(t *testing.T) {
	if _, err := Load("../../testdata/keystores/does-not-exist"); err == nil {
		t.Fatal("expected an error for a missing keystore directory")
	}
}

func TestHas(t *testing.T) {
	set, err := Load("../../testdata/keystores/clean")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !set.Has(pubA) {
		t.Errorf("Has(%s) = false, want true", pubA)
	}
	if set.Has(pubC) {
		t.Errorf("Has(%s) = true, want false", pubC)
	}
}

func TestNormalizePubkey(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		valid bool
	}{
		{strings.ToUpper(pubA[2:]), pubA, true},
		{pubA, pubA, true},
		{" " + pubA + " ", pubA, true},
		{"0xdeadbeef", "0xdeadbeef", false},
		{"", "0x", false},
		{"0x" + strings.Repeat("z", 96), "0x" + strings.Repeat("z", 96), false},
	}
	for _, c := range cases {
		got, ok := NormalizePubkey(c.in)
		if got != c.want || ok != c.valid {
			t.Errorf("NormalizePubkey(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.valid)
		}
	}
}
