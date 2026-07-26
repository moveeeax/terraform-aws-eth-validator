package interchange

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "../../testdata/interchange"

func parseFixture(t *testing.T, name string) *File {
	t.Helper()
	f, err := os.Open(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	doc, err := Parse(f)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return doc
}

func TestParseCleanExport(t *testing.T) {
	doc := parseFixture(t, "clean.json")
	if doc.Metadata.FormatVersion != FormatVersion {
		t.Errorf("format version = %q, want %q", doc.Metadata.FormatVersion, FormatVersion)
	}
	if len(doc.Data) != 2 {
		t.Fatalf("records = %d, want 2", len(doc.Data))
	}
	first := doc.Data[0]
	if len(first.SignedBlocks) != 2 {
		t.Errorf("signed blocks = %d, want 2", len(first.SignedBlocks))
	}
	slot := first.SignedBlocks[0].Slot
	if !slot.Valid || slot.Value != 3840100 {
		t.Errorf("slot = %+v, want value 3840100", slot)
	}
	if !slot.Quoted {
		t.Error("slot should be recorded as string-encoded, as EIP-3076 requires")
	}
}

func TestParseAcceptsNumericEncodingAndFlagsIt(t *testing.T) {
	doc := parseFixture(t, "malformed.json")
	var numberEncoded int
	for _, rec := range doc.Data {
		for _, a := range rec.SignedAttestations {
			if a.SourceEpoch.Set && !a.SourceEpoch.Quoted {
				numberEncoded++
			}
		}
	}
	if numberEncoded == 0 {
		t.Fatal("expected at least one bare-JSON-number epoch in the fixture")
	}
}

func TestParseKeepsUnparseableValues(t *testing.T) {
	doc := parseFixture(t, "malformed.json")
	slot := doc.Data[0].SignedBlocks[0].Slot
	if slot.Valid {
		t.Errorf("slot %q should not parse as uint64", slot.Raw)
	}
	if slot.Raw != "0x3a" {
		t.Errorf("raw slot = %q, want %q", slot.Raw, "0x3a")
	}
	if !slot.Set {
		t.Error("slot should be marked as present")
	}
}

func TestParseRejectsTrailingContent(t *testing.T) {
	_, err := Parse(strings.NewReader(`{"metadata":{},"data":[]}{"metadata":{}}`))
	if err == nil {
		t.Fatal("expected an error for trailing content")
	}
	if !strings.Contains(err.Error(), "trailing content") {
		t.Errorf("error = %v, want it to mention trailing content", err)
	}
}

func TestParseRejectsNonJSON(t *testing.T) {
	if _, err := Parse(strings.NewReader("not json at all")); err == nil {
		t.Fatal("expected an error for a non-JSON document")
	}
}

func TestMaxTargetEpoch(t *testing.T) {
	doc := parseFixture(t, "clean.json")
	got, ok := doc.MaxTargetEpoch()
	if !ok {
		t.Fatal("expected a max target epoch")
	}
	if got != 120003 {
		t.Errorf("max target epoch = %d, want 120003", got)
	}

	empty := &File{}
	if _, ok := empty.MaxTargetEpoch(); ok {
		t.Error("an empty export has no max target epoch")
	}
}
