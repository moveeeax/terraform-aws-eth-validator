// Package audit applies the slashing-protection rule set to a parsed
// EIP-3076 export and the key set of the host that is about to load it.
//
// Every finding carries a failure sequence: the ordered steps by which the
// condition turns into a slashed validator. A finding without one is a lint
// warning, and lint warnings do not get an operator out of bed.
package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/moveeeax/terraform-aws-eth-validator/internal/interchange"
	"github.com/moveeeax/terraform-aws-eth-validator/internal/keystore"
)

// Severity ranks a finding.
type Severity string

const (
	Info     Severity = "info"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

var rank = map[Severity]int{Info: 0, Medium: 1, High: 2, Critical: 3}

// Rank returns the comparable weight of a severity. Unknown values rank
// lowest so a typo in --fail-on can never silently suppress a finding.
func (s Severity) Rank() int { return rank[s] }

// ParseSeverity maps a CLI string onto a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case Info:
		return Info, nil
	case Medium:
		return Medium, nil
	case High:
		return High, nil
	case Critical:
		return Critical, nil
	}
	return "", fmt.Errorf("unknown severity %q (want info, medium, high or critical)", s)
}

// Finding is one problem with the export or the key set.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Subject  string   `json:"subject,omitempty"`
	Detail   string   `json:"detail"`
	Failure  []string `json:"failure_sequence"`
	Remedy   string   `json:"remediation"`
}

// Skipped is a check that could not run because an input was not supplied.
// Skipped checks are reported: a green run that quietly skipped half the rule
// set is worse than a red one.
type Skipped struct {
	Rule   string `json:"rule"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// Options are the operator-supplied facts the rule set needs.
type Options struct {
	// GenesisValidatorsRoot is the value read from the beacon node that will
	// serve this validator. Empty disables the network-match check.
	GenesisValidatorsRoot string
	// CurrentEpoch is the head epoch at the time of the restore. Zero with
	// HaveCurrentEpoch false disables the staleness check.
	CurrentEpoch     uint64
	HaveCurrentEpoch bool
	// MaxEpochLag is how far behind head the newest record in the export may
	// be before the export is treated as stale.
	MaxEpochLag uint64
}

// Report is the full result of a run.
type Report struct {
	InterchangeFile string    `json:"interchange_file"`
	KeystoreDir     string    `json:"keystore_dir,omitempty"`
	FormatVersion   string    `json:"format_version"`
	KeysOnDisk      int       `json:"keys_on_disk"`
	KeysInExport    int       `json:"keys_in_export"`
	KeysProtected   int       `json:"keys_protected"`
	Findings        []Finding `json:"findings"`
	Skipped         []Skipped `json:"skipped_checks"`
}

// Worst returns the highest severity present, or Info when there is nothing.
func (r Report) Worst() Severity {
	worst := Info
	for _, f := range r.Findings {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return worst
}

// CountAtOrAbove returns how many findings are at least as severe as min.
func (r Report) CountAtOrAbove(min Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity.Rank() >= min.Rank() {
			n++
		}
	}
	return n
}

// Run applies every rule. ks may be nil when no keystore directory was given.
func Run(f *interchange.File, ks *keystore.Set, opt Options) Report {
	rep := Report{FormatVersion: f.Metadata.FormatVersion}
	if ks != nil {
		rep.KeystoreDir = ks.Dir
		rep.KeysOnDisk = len(ks.Keys)
	}

	add := func(fs ...Finding) { rep.Findings = append(rep.Findings, fs...) }

	add(checkFormatVersion(f)...)
	add(checkGenesisRoot(f, opt, &rep)...)

	inExport, dupFindings := indexRecords(f)
	rep.KeysInExport = len(inExport)
	add(dupFindings...)
	add(checkRecords(f)...)
	add(checkCoverage(inExport, ks, &rep)...)
	add(checkStaleness(f, opt, &rep)...)

	if ks != nil {
		for _, s := range ks.Skipped {
			add(Finding{
				Rule:     "SP014",
				Severity: Medium,
				Title:    "file in the keystore directory could not be read as a keystore",
				Subject:  s.File,
				Detail:   fmt.Sprintf("%s was skipped (%s), so its public key is unknown to this audit.", s.File, s.Reason),
				Failure: []string{
					"The audit reports full coverage because it never saw the key in that file.",
					"The validator client is more forgiving than this tool and loads the key anyway.",
					"The key starts signing with no protection record.",
					"If the same key is loaded anywhere else, the two instances double-sign.",
				},
				Remedy: "Fix or remove the file, then re-run. A validator key directory should contain nothing but readable keystores.",
			})
		}
	}

	sortFindings(rep.Findings)
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	if rep.Skipped == nil {
		rep.Skipped = []Skipped{}
	}
	return rep
}

func checkFormatVersion(f *interchange.File) []Finding {
	if f.Metadata.FormatVersion == interchange.FormatVersion {
		return nil
	}
	got := f.Metadata.FormatVersion
	if got == "" {
		got = "(absent)"
	}
	return []Finding{{
		Rule:     "SP001",
		Severity: Critical,
		Title:    "unsupported interchange format version",
		Detail: fmt.Sprintf("interchange_format_version is %s, expected %q. This file is not an EIP-3076 v5 export.",
			got, interchange.FormatVersion),
		Failure: []string{
			"The validator client rejects the import, or accepts a subset of it.",
			"The operator sees a healthy beacon node and starts the validator anyway.",
			"The client begins from an empty slashing-protection database.",
			"It signs an attestation for an epoch the same key already attested in, which is a slashable double vote.",
		},
		Remedy: "Re-export with the client that owns the keys. Do not hand-edit the file to change the version.",
	}}
}

func checkGenesisRoot(f *interchange.File, opt Options, rep *Report) []Finding {
	got, ok := normalizeRoot(f.Metadata.GenesisValidatorsRoot)
	if !ok {
		return []Finding{{
			Rule:     "SP003",
			Severity: High,
			Title:    "genesis_validators_root is missing or malformed",
			Detail: fmt.Sprintf("metadata.genesis_validators_root is %q, which is not a 32-byte hex value.",
				f.Metadata.GenesisValidatorsRoot),
			Failure: []string{
				"Nothing pins this export to a chain.",
				"An importer that does not enforce the field accepts it against any network.",
				"The protection database is populated with epochs from a chain the validator is not on.",
				"On the real chain the high-water mark is wrong in both directions, and the first signature after the restore can be a double vote or a surround vote.",
			},
			Remedy: "Re-export from the source client. Confirm the root against the target beacon node: curl -s $BEACON/eth/v1/beacon/genesis | jq -r .data.genesis_validators_root",
		}}
	}
	if opt.GenesisValidatorsRoot == "" {
		rep.Skipped = append(rep.Skipped, Skipped{
			Rule:   "SP002",
			Title:  "export matches the target network",
			Reason: "--genesis-validators-root was not supplied",
		})
		return nil
	}
	want, wantOK := normalizeRoot(opt.GenesisValidatorsRoot)
	if !wantOK {
		rep.Skipped = append(rep.Skipped, Skipped{
			Rule:   "SP002",
			Title:  "export matches the target network",
			Reason: "--genesis-validators-root is not a 32-byte hex value",
		})
		return nil
	}
	if got == want {
		return nil
	}
	return []Finding{{
		Rule:     "SP002",
		Severity: Critical,
		Title:    "export belongs to a different chain than the target beacon node",
		Detail:   fmt.Sprintf("export genesis_validators_root is %s, the target network is %s.", got, want),
		Failure: []string{
			"The export was taken from a validator running on another chain, most often a testnet rehearsal of the same procedure.",
			"Importing it fills the protection database with epochs that never happened on this chain.",
			"The client now believes it is protected and starts signing immediately.",
			"There is no record of what the key actually signed on this chain before the restore, so the first attestation can duplicate one already on-chain.",
		},
		Remedy: "Stop. Find the export taken from the instance that was signing on this chain and use that one. Never import across networks.",
	}}
}

// indexRecords maps normalised pubkeys to their records and reports keys that
// appear more than once.
func indexRecords(f *interchange.File) (map[string][]interchange.Record, []Finding) {
	idx := map[string][]interchange.Record{}
	order := []string{}
	for _, rec := range f.Data {
		norm, _ := keystore.NormalizePubkey(rec.Pubkey)
		if _, seen := idx[norm]; !seen {
			order = append(order, norm)
		}
		idx[norm] = append(idx[norm], rec)
	}
	var out []Finding
	for _, pk := range order {
		recs := idx[pk]
		if len(recs) < 2 {
			continue
		}
		out = append(out, Finding{
			Rule:     "SP005",
			Severity: Critical,
			Title:    "duplicate public key in the export",
			Subject:  pk,
			Detail:   fmt.Sprintf("%s appears %d times with separate histories.", pk, len(recs)),
			Failure: []string{
				"Two entries for one key carry two different histories.",
				"EIP-3076 does not require importers to merge them; most keep the last entry they read.",
				"The high-water mark drops to whatever the losing entry contained.",
				"The client signs below its true high-water mark and produces a surround vote against its own earlier attestation.",
			},
			Remedy: "Merge the histories into one record per key, keeping the highest slot and the highest source/target pair, and re-run this check before importing.",
		})
	}
	return idx, out
}

func checkRecords(f *interchange.File) []Finding {
	var out []Finding
	nonConformant := 0
	for _, rec := range f.Data {
		norm, ok := keystore.NormalizePubkey(rec.Pubkey)
		if !ok {
			out = append(out, Finding{
				Rule:     "SP011",
				Severity: High,
				Title:    "malformed validator public key",
				Subject:  rec.Pubkey,
				Detail:   "a record's pubkey is not 48 bytes of hex, so it cannot be matched against a keystore.",
				Failure: []string{
					"The importer either rejects the record or stores it under a key that will never be looked up.",
					"The real key on disk therefore has no protection record.",
					"It signs from a zero high-water mark on the next slot it is scheduled for.",
					"Anything that key already signed becomes a candidate for a double vote.",
				},
				Remedy: "Re-export from the source client rather than repairing the file by hand.",
			})
			continue
		}
		if len(rec.SignedBlocks) == 0 && len(rec.SignedAttestations) == 0 {
			out = append(out, Finding{
				Rule:     "SP006",
				Severity: High,
				Title:    "validator key has an empty signing history",
				Subject:  norm,
				Detail:   "the record contains no signed blocks and no signed attestations.",
				Failure: []string{
					"After import the high-water mark for this key is zero, which is indistinguishable from a key that has never signed.",
					"Every epoch now looks safe to attest.",
					"The client attests for the current epoch.",
					"If this key was active before the restore, that epoch may already carry its signature, which is a double vote.",
				},
				Remedy: "Confirm the key really has never signed. If it has, re-export from the instance that holds its history; an empty record is not a substitute.",
			})
		}
		for _, b := range rec.SignedBlocks {
			if !b.Slot.Valid {
				out = append(out, malformedNumber("SP010", norm, "signed_blocks[].slot", b.Slot.Raw))
			} else if b.Slot.Set && !b.Slot.Quoted {
				nonConformant++
			}
		}
		for _, a := range rec.SignedAttestations {
			switch {
			case !a.SourceEpoch.Valid:
				out = append(out, malformedNumber("SP010", norm, "signed_attestations[].source_epoch", a.SourceEpoch.Raw))
			case !a.TargetEpoch.Valid:
				out = append(out, malformedNumber("SP010", norm, "signed_attestations[].target_epoch", a.TargetEpoch.Raw))
			case a.SourceEpoch.Value > a.TargetEpoch.Value:
				out = append(out, Finding{
					Rule:     "SP007",
					Severity: Critical,
					Title:    "attestation record has source epoch after target epoch",
					Subject:  norm,
					Detail: fmt.Sprintf("source_epoch %d is greater than target_epoch %d, which no valid attestation can produce.",
						a.SourceEpoch.Value, a.TargetEpoch.Value),
					Failure: []string{
						"The record is either rejected by a conformant importer or stored inverted.",
						"The surround-vote bound for this key is now computed from a pair that cannot be satisfied.",
						"The client either refuses to sign at all, which is downtime, or accepts a vote that surrounds one it already made.",
						"A surround vote is slashable on its own, with no second instance involved.",
					},
					Remedy: "Treat the export as corrupt. Re-export from the source client and compare the record count before importing.",
				})
			}
			if a.SourceEpoch.Set && !a.SourceEpoch.Quoted {
				nonConformant++
			}
			if a.TargetEpoch.Set && !a.TargetEpoch.Quoted {
				nonConformant++
			}
		}
	}
	if nonConformant > 0 {
		out = append(out, Finding{
			Rule:     "SP013",
			Severity: Info,
			Title:    "slots and epochs encoded as JSON numbers",
			Detail: fmt.Sprintf("%d numeric fields are bare JSON numbers; EIP-3076 requires decimal strings.",
				nonConformant),
			Failure: []string{
				"Strict importers reject the file outright, which shows up as an unexplained import failure during a restore window.",
				"Lenient importers accept it, so the same file behaves differently on two clients.",
				"An operator who switches clients mid-incident discovers the difference at the worst moment.",
			},
			Remedy: "Usable as-is, but note the exporting client and version in the runbook so a client switch does not surprise the next operator.",
		})
	}
	return out
}

func malformedNumber(rule, subject, field, raw string) Finding {
	return Finding{
		Rule:     rule,
		Severity: Critical,
		Title:    "malformed slot or epoch value",
		Subject:  subject,
		Detail:   fmt.Sprintf("%s is %q, which is not a uint64.", field, raw),
		Failure: []string{
			"The importer cannot place this record on the epoch line.",
			"Depending on the client the record is dropped or the whole key is skipped.",
			"The key ends up with a high-water mark below the epochs it has already signed.",
			"The next scheduled duty re-signs an epoch that is already on-chain.",
		},
		Remedy: "Do not repair the file by hand. Re-export from the client that owns the key.",
	}
}

func checkCoverage(inExport map[string][]interchange.Record, ks *keystore.Set, rep *Report) []Finding {
	if ks == nil {
		rep.Skipped = append(rep.Skipped, Skipped{
			Rule:   "SP004",
			Title:  "every key on disk is covered by the export",
			Reason: "--keystores was not supplied",
		})
		rep.Skipped = append(rep.Skipped, Skipped{
			Rule:   "SP009",
			Title:  "the export contains no keys this host does not hold",
			Reason: "--keystores was not supplied",
		})
		return nil
	}
	var out []Finding
	for _, k := range ks.Keys {
		if _, ok := inExport[k.Pubkey]; ok {
			rep.KeysProtected++
			continue
		}
		out = append(out, Finding{
			Rule:     "SP004",
			Severity: Critical,
			Title:    "keystore on this host has no slashing-protection record",
			Subject:  k.Pubkey,
			Detail:   fmt.Sprintf("%s is present in %s but absent from the export.", k.File, ks.Dir),
			Failure: []string{
				"The validator client loads the keystore at start-up.",
				"No protection record exists for the key, so the client treats it as never having signed.",
				"The key signs an attestation for the current epoch as soon as it is scheduled.",
				"If the key signed at that epoch on the host being replaced, the two messages are a slashable double vote.",
			},
			Remedy: "Do not start the validator client. Either export the missing key's history from the instance that has it, or remove the keystore from this host until you can.",
		})
	}
	for pk := range inExport {
		if ks.Has(pk) {
			continue
		}
		out = append(out, Finding{
			Rule:     "SP009",
			Severity: Medium,
			Title:    "export covers a key this host does not hold",
			Subject:  pk,
			Detail:   fmt.Sprintf("%s is in the export but has no keystore in %s.", pk, ks.Dir),
			Failure: []string{
				"Not slashable by itself.",
				"It means the export and the keystore directory came from different key sets.",
				"The usual cause is a partial key move, and the keys left behind are still loaded on the old host.",
				"Two hosts holding overlapping key sets is the most common route into a double-signing incident.",
			},
			Remedy: "Account for every key in the export. Confirm the old host is stopped and its keystores removed before this one starts.",
		})
	}
	return out
}

func checkStaleness(f *interchange.File, opt Options, rep *Report) []Finding {
	if !opt.HaveCurrentEpoch {
		rep.Skipped = append(rep.Skipped, Skipped{
			Rule:   "SP008",
			Title:  "export is recent enough to be trusted",
			Reason: "--current-epoch was not supplied",
		})
		return nil
	}
	maxTarget, ok := f.MaxTargetEpoch()
	if !ok {
		// Nothing to measure. SP006 already covers the empty-history case.
		rep.Skipped = append(rep.Skipped, Skipped{
			Rule:   "SP008",
			Title:  "export is recent enough to be trusted",
			Reason: "the export contains no usable attestation records to date it",
		})
		return nil
	}
	if maxTarget > opt.CurrentEpoch {
		return []Finding{{
			Rule:     "SP012",
			Severity: High,
			Title:    "export contains epochs in the future",
			Detail: fmt.Sprintf("the newest attestation target epoch is %d but head is %d.",
				maxTarget, opt.CurrentEpoch),
			Failure: []string{
				"Either the export is from a different chain, or the epoch supplied to this check is wrong.",
				"If the export is foreign, importing it blocks legitimate signing until head catches up, which is silent downtime.",
				"If the epoch is wrong, the staleness check below it is meaningless and a stale export passes unnoticed.",
			},
			Remedy: "Re-read head from the target beacon node and confirm the genesis root before continuing.",
		}}
	}
	lag := opt.CurrentEpoch - maxTarget
	if lag <= opt.MaxEpochLag {
		return nil
	}
	return []Finding{{
		Rule:     "SP008",
		Severity: High,
		Title:    "slashing-protection export is stale",
		Detail: fmt.Sprintf("the newest attestation target epoch is %d, %d epochs behind head (%d); the limit is %d.",
			maxTarget, lag, opt.CurrentEpoch, opt.MaxEpochLag),
		Failure: []string{
			"The export is older than the last messages the validator actually signed.",
			"Importing it restores a high-water mark that has already been passed on-chain.",
			"The client considers the epochs between the export and head unsigned and attests in them.",
			"Those epochs already carry a signature from the instance that produced them, which is a double vote.",
		},
		Remedy: "Take a fresh export from the running instance, or if that instance is unreachable, wait out the weak-subjectivity gap before signing rather than importing an old file.",
	}}
}

func normalizeRoot(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 64 {
		return "0x" + s, false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "0x" + s, false
		}
	}
	return "0x" + s, true
}

// sortFindings gives a stable, review-friendly order: worst first, then rule
// id, then subject.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Subject < b.Subject
	})
}
