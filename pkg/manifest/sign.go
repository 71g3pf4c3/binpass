package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
)

// Signed is a manifest together with its Ed25519 signature and public key.
type Signed struct {
	// Manifest is the canonical JSON encoding of the manifest.
	Manifest []byte `json:"manifest"`
	// Signature is Ed25519 over signingInput(Generation, StoreID, Manifest).
	Signature []byte `json:"signature"`
	// PublicKey is the store signing public key.
	PublicKey []byte `json:"public_key"`
}

// Canonical returns a deterministic JSON encoding of the manifest: map keys
// are sorted and there is no insignificant whitespace, so identical manifests
// always produce identical bytes (and therefore identical signatures).
func Canonical(m *Manifest) ([]byte, error) {
	// json.Marshal already sorts map keys; we additionally sort the string
	// slices inside entries for determinism and disable HTML escaping.
	norm := m.Clone()
	for k, e := range norm.Entries {
		if len(e.Chunks) > 1 {
			e.Chunks = append([]string(nil), e.Chunks...)
			// Chunk order is significant for reassembly, so do NOT sort chunks.
		}
		norm.Entries[k] = e
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(norm); err != nil {
		return nil, fmt.Errorf("manifest: canonical: %w", err)
	}
	// Encoder appends a trailing newline; trim it for a stable digest.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// signingInput builds the bytes that are actually signed:
// generation (8 bytes big-endian) || storeID || sha256(canonicalManifest).
func signingInput(generation uint64, storeID string, canonical []byte) []byte {
	var b bytes.Buffer
	var g [8]byte
	binary.BigEndian.PutUint64(g[:], generation)
	b.Write(g[:])
	b.WriteString(storeID)
	sum := sha256.Sum256(canonical)
	b.Write(sum[:])
	return b.Bytes()
}

// Sign canonicalises and signs the manifest with priv.
func Sign(m *Manifest, priv ed25519.PrivateKey) (*Signed, error) {
	canonical, err := Canonical(m)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, signingInput(m.Generation, m.StoreID, canonical))
	return &Signed{
		Manifest:  canonical,
		Signature: sig,
		PublicKey: append([]byte(nil), priv.Public().(ed25519.PublicKey)...),
	}, nil
}

// Verify checks the signature and decodes the manifest. It optionally enforces
// that the embedded public key equals expectKey (nil to skip) and that the
// generation is at least minGeneration (rollback protection).
func Verify(s *Signed, expectKey ed25519.PublicKey, minGeneration uint64) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(s.Manifest, &m); err != nil {
		return nil, fmt.Errorf("manifest: decode: %w", err)
	}
	if expectKey != nil && !bytes.Equal(expectKey, s.PublicKey) {
		return nil, fmt.Errorf("manifest: unexpected signing key")
	}
	if !ed25519.Verify(ed25519.PublicKey(s.PublicKey), signingInput(m.Generation, m.StoreID, s.Manifest), s.Signature) {
		return nil, fmt.Errorf("manifest: bad signature")
	}
	if m.Generation < minGeneration {
		return nil, fmt.Errorf("manifest: rollback detected (gen %d < %d)", m.Generation, minGeneration)
	}
	return &m, nil
}

// SortedPaths returns the entry paths in sorted order for deterministic
// iteration.
func (m *Manifest) SortedPaths() []string {
	out := make([]string, 0, len(m.Entries))
	for k := range m.Entries {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
