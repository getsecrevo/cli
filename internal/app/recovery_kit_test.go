package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecoveryKitRoundTrip(t *testing.T) {
	t.Parallel()

	plaintext := []byte(`{"workspace_id":"workspace-0001","secrets":[{"name":"OPENAI_API_KEY","value":"sk-live-xyz"}]}`)
	passphrase, err := generateKitPassphrase()
	if err != nil {
		t.Fatalf("generateKitPassphrase err = %v", err)
	}
	if len(passphrase) < 40 {
		t.Fatalf("passphrase length = %d, want >= 40 base64 chars", len(passphrase))
	}

	blob, err := encryptRecoveryKit(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encrypt err = %v", err)
	}
	if !strings.HasPrefix(string(blob), kitMagic) {
		t.Fatalf("blob missing magic prefix")
	}

	recovered, err := decryptRecoveryKit(blob, passphrase)
	if err != nil {
		t.Fatalf("decrypt err = %v", err)
	}
	if !bytes.Equal(plaintext, recovered) {
		t.Fatalf("round-trip mismatch:\n got:  %s\n want: %s", recovered, plaintext)
	}
}

func TestRecoveryKitDecryptWithWrongPassphraseFails(t *testing.T) {
	t.Parallel()

	blob, err := encryptRecoveryKit([]byte("hello"), "correct-passphrase")
	if err != nil {
		t.Fatalf("encrypt err = %v", err)
	}
	if _, err := decryptRecoveryKit(blob, "wrong-passphrase"); err == nil {
		t.Fatalf("expected decrypt to fail with wrong passphrase")
	}
}

func TestRecoveryKitRejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()

	passphrase := "the-right-key"
	blob, err := encryptRecoveryKit([]byte("hello"), passphrase)
	if err != nil {
		t.Fatalf("encrypt err = %v", err)
	}
	// Flip a byte in the ciphertext region (after the 45-byte header).
	blob[len(blob)-1] ^= 0xFF
	if _, err := decryptRecoveryKit(blob, passphrase); err == nil {
		t.Fatalf("expected decrypt to fail when ciphertext is tampered (GCM auth)")
	}
}

func TestRecoveryKitRejectsBadMagic(t *testing.T) {
	t.Parallel()

	if _, err := decryptRecoveryKit([]byte("not a kit"), "anything"); err == nil {
		t.Fatalf("expected error for bad magic")
	}
}

func TestRecoveryKitPassphrasesAreUnique(t *testing.T) {
	t.Parallel()
	// Sanity check: two consecutive calls must not produce the same passphrase.
	a, _ := generateKitPassphrase()
	b, _ := generateKitPassphrase()
	if a == b {
		t.Fatalf("two passphrases collided: %s == %s", a, b)
	}
}
