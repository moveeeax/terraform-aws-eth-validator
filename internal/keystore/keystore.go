// Package keystore reads the public keys out of a directory of EIP-2335
// validator keystore files.
//
// Only the "pubkey" field is read. The tool never decrypts a keystore, never
// asks for a password and never touches the secret material — it only needs
// to know which keys a host is about to load.
package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Key is one keystore file on disk.
type Key struct {
	Pubkey string `json:"pubkey"` // normalised: lowercase, 0x-prefixed
	File   string `json:"file"`
}

// Skip records a file that was present but not usable as a keystore.
type Skip struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// Set is the result of scanning a keystore directory.
type Set struct {
	Dir     string
	Keys    []Key
	Skipped []Skip
}

// Has reports whether the set contains a normalised public key.
func (s *Set) Has(pubkey string) bool {
	for _, k := range s.Keys {
		if k.Pubkey == pubkey {
			return true
		}
	}
	return false
}

// NormalizePubkey lowercases a BLS public key and gives it a 0x prefix.
// Interchange files carry the prefix, EIP-2335 keystores usually do not.
// ok is false when the result is not 48 bytes of hex.
func NormalizePubkey(s string) (norm string, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 96 {
		return "0x" + s, false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "0x" + s, false
		}
	}
	return "0x" + s, true
}

// Load scans dir (non-recursively) for *.json keystore files.
//
// deposit_data-*.json files are ignored on purpose: they are a JSON array of
// deposits, they also contain a "pubkey" field, and counting them as loadable
// keys would silently inflate the key count of the host.
func Load(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read keystore dir: %w", err)
	}
	set := &Set{Dir: dir}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		if strings.HasPrefix(e.Name(), "deposit_data") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			set.Skipped = append(set.Skipped, Skip{File: e.Name(), Reason: "unreadable: " + err.Error()})
			continue
		}
		var ks struct {
			Pubkey string `json:"pubkey"`
		}
		if err := json.Unmarshal(b, &ks); err != nil {
			set.Skipped = append(set.Skipped, Skip{File: e.Name(), Reason: "not a JSON object"})
			continue
		}
		if ks.Pubkey == "" {
			set.Skipped = append(set.Skipped, Skip{File: e.Name(), Reason: "no pubkey field"})
			continue
		}
		norm, _ := NormalizePubkey(ks.Pubkey)
		set.Keys = append(set.Keys, Key{Pubkey: norm, File: e.Name()})
	}
	sort.Slice(set.Keys, func(i, j int) bool { return set.Keys[i].Pubkey < set.Keys[j].Pubkey })
	sort.Slice(set.Skipped, func(i, j int) bool { return set.Skipped[i].File < set.Skipped[j].File })
	return set, nil
}
