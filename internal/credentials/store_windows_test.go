//go:build windows

package credentials

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestProtectRoundTrip exercises the DPAPI layer directly. The test
// asserts on length / SHA-256 fingerprint rather than echoing the
// (here, synthetic) token bytes to test output — credentials and
// token-shaped values must never reach stdout per
// smoke_tests_never_print_secret_values policy.
func TestProtectRoundTrip(t *testing.T) {
	want := []byte(`{"version":1,"token":"agt_synthetic"}`)
	wantSum := sha256.Sum256(want)

	cipher, wrapped, err := protect(want)
	if err != nil {
		t.Fatalf("protect() error = %v", err)
	}
	if !wrapped {
		t.Fatalf("protect() wrapped = false on Windows; expected true")
	}
	if len(cipher) == 0 {
		t.Fatalf("protect() returned empty ciphertext")
	}
	if bytes.Equal(cipher, want) {
		t.Fatalf("protect() returned plaintext unchanged")
	}

	got, err := unprotect(cipher)
	if err != nil {
		t.Fatalf("unprotect() error = %v", err)
	}
	gotSum := sha256.Sum256(got)
	if gotSum != wantSum {
		t.Fatalf("round-trip digest mismatch: got %s want %s",
			hex.EncodeToString(gotSum[:]), hex.EncodeToString(wantSum[:]))
	}
	if len(got) != len(want) {
		t.Fatalf("round-trip length mismatch: got %d want %d", len(got), len(want))
	}
}

// TestSaveWritesMagicHeader verifies the on-disk layout: 8-byte magic
// + DPAPI ciphertext, with the JSON token bytes not present in the
// clear anywhere in the file.
func TestSaveWritesMagicHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")

	in := File{
		BaseURL:     "https://api.secrevo.com",
		WorkspaceID: "ws-1",
		Token:       "agt_synthetic_header_test",
	}
	if err := Save(path, in); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if len(raw) < len(magic) {
		t.Fatalf("file shorter than magic header: len=%d", len(raw))
	}
	if !bytes.Equal(raw[:len(magic)], magic) {
		t.Fatalf("missing magic header: first bytes len=%d", len(raw[:len(magic)]))
	}
	if bytes.Contains(raw, []byte(in.Token)) {
		t.Fatalf("token bytes appear in clear on disk; DPAPI wrap failed")
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Token != in.Token || got.BaseURL != in.BaseURL || got.WorkspaceID != in.WorkspaceID {
		// Don't print the token; report which field diverged.
		t.Fatalf("round-trip field mismatch: token-match=%t baseurl-match=%t workspace-match=%t",
			got.Token == in.Token, got.BaseURL == in.BaseURL, got.WorkspaceID == in.WorkspaceID)
	}
}

// TestLoadLegacyPlainJSONAndAutoMigrate verifies back-compat: a
// credentials file written by a previous CLI version (plain JSON, no
// magic header) loads correctly, and the next Save call writes the
// file in the new wrapped format.
func TestLoadLegacyPlainJSONAndAutoMigrate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")

	legacy := File{
		Version:     1,
		BaseURL:     "https://api.secrevo.com",
		WorkspaceID: "ws-legacy",
		Token:       "agt_legacy_synthetic",
	}
	plain, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	if err := os.WriteFile(path, plain, 0o600); err != nil {
		t.Fatalf("seed legacy file: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() legacy error = %v", err)
	}
	if loaded.Token != legacy.Token {
		t.Fatalf("legacy load token mismatch (token-match=%t)", loaded.Token == legacy.Token)
	}

	if err := Save(path, loaded); err != nil {
		t.Fatalf("Save() after legacy load error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() post-save error = %v", err)
	}
	if len(raw) < len(magic) || !bytes.Equal(raw[:len(magic)], magic) {
		t.Fatalf("Save() did not migrate legacy file to wrapped format")
	}
	if bytes.Contains(raw, []byte(legacy.Token)) {
		t.Fatalf("token bytes still in clear after migration")
	}
}

// TestLoadShorterThanMagicIsTreatedAsLegacy ensures a tiny file (e.g.
// an empty `{}` placeholder shorter than 8 bytes — defensive, not
// expected in practice) is routed through the plain-JSON path and
// surfaces a parser error rather than panicking on a slice bounds.
func TestLoadShorterThanMagicIsTreatedAsLegacy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed tiny file: %v", err)
	}
	// The file is shorter than the magic header, so Load takes the
	// legacy plain-JSON path. JSON parses fine but `version` is 0,
	// so the unsupported-version branch fires — that's the expected
	// failure mode for a corrupt/placeholder file.
	if _, err := Load(path); err == nil {
		t.Fatalf("Load() of tiny file should fail with unsupported version, got nil")
	}
}
