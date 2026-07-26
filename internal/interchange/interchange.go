// Package interchange parses the EIP-3076 slashing-protection interchange
// format.
//
// Parsing is deliberately lenient: a malformed field is recorded rather than
// returned as an error, because the point of the tool is to report every
// problem in one pass instead of stopping at the first one. Only a document
// that is not valid JSON, or whose top level is not the expected shape, is a
// hard failure.
package interchange

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// FormatVersion is the only interchange_format_version this tool accepts.
// EIP-3076 has been at version 5 since the format was finalised; anything
// else is either a pre-release export or a different document entirely.
const FormatVersion = "5"

// Num is a uint64 field of the interchange format.
//
// EIP-3076 mandates that slots and epochs are encoded as decimal *strings*.
// Some clients have shipped exports that encode them as JSON numbers, so both
// encodings are accepted and the original form is retained: an audit wants to
// know that an export is non-conformant even when it is still usable.
type Num struct {
	Raw    string // the value exactly as it appeared in the document
	Value  uint64
	Valid  bool // Raw parsed as a base-10 uint64
	Quoted bool // encoded as a JSON string, as the spec requires
	Set    bool // the field was present at all
}

// UnmarshalJSON never fails. An unparseable value is kept in Raw with Valid
// false so the audit can attribute it to a specific record.
func (n *Num) UnmarshalJSON(b []byte) error {
	n.Set = true
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			n.Raw = string(b)
			return nil
		}
		n.Raw, n.Quoted = s, true
	} else {
		n.Raw = string(b)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(n.Raw), 10, 64)
	if err != nil {
		return nil
	}
	n.Value, n.Valid = v, true
	return nil
}

// MarshalJSON re-emits the value in the spec-mandated string form.
func (n Num) MarshalJSON() ([]byte, error) { return json.Marshal(n.Raw) }

// Metadata is the interchange header.
type Metadata struct {
	FormatVersion         string `json:"interchange_format_version"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
}

// SignedBlock is one block-proposal record.
type SignedBlock struct {
	Slot        Num    `json:"slot"`
	SigningRoot string `json:"signing_root,omitempty"`
}

// SignedAttestation is one attestation record.
type SignedAttestation struct {
	SourceEpoch Num    `json:"source_epoch"`
	TargetEpoch Num    `json:"target_epoch"`
	SigningRoot string `json:"signing_root,omitempty"`
}

// Record is the signing history of a single validator public key.
type Record struct {
	Pubkey             string              `json:"pubkey"`
	SignedBlocks       []SignedBlock       `json:"signed_blocks"`
	SignedAttestations []SignedAttestation `json:"signed_attestations"`
}

// File is a parsed interchange document.
type File struct {
	Metadata Metadata `json:"metadata"`
	Data     []Record `json:"data"`
}

// Parse reads an interchange document. Trailing content after the JSON value
// is an error: a truncated-then-appended export is a real failure mode when
// somebody copies a file mid-write off a running host.
func Parse(r io.Reader) (*File, error) {
	dec := json.NewDecoder(r)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode interchange: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("decode interchange: trailing content after the JSON document")
	}
	return &f, nil
}

// MaxTargetEpoch returns the highest attestation target epoch across every
// record, which is the closest thing the export has to a "taken at" marker.
func (f *File) MaxTargetEpoch() (uint64, bool) {
	var max uint64
	var ok bool
	for _, rec := range f.Data {
		for _, a := range rec.SignedAttestations {
			if a.TargetEpoch.Valid && (!ok || a.TargetEpoch.Value > max) {
				max, ok = a.TargetEpoch.Value, true
			}
		}
	}
	return max, ok
}
