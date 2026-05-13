package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// File format for the Secrevo recovery kit ciphertext:
//
//	bytes [ 0..13)  magic       = "SECREVOKIT01\n"
//	bytes [13..17)  iters       = uint32 big-endian (PBKDF2 iterations)
//	bytes [17..33)  salt        = 16 random bytes
//	bytes [33..45)  nonce       = 12 random bytes (AES-GCM standard)
//	bytes [45..)    ciphertext  = AES-256-GCM(plaintext) with auth tag appended
//
// Key derivation: PBKDF2-HMAC-SHA256(passphrase, salt, iters, 32-byte key).
//
// The dashboard regenerates kits via WebCrypto using the same primitives so
// a kit produced by the CLI is decryptable in the browser and vice-versa.
//
// Operators can decrypt without our CLI in a pinch: a 30-line Python script
// against this format with `cryptography.hazmat` is enough.
const (
	kitMagic    = "SECREVOKIT01\n"
	kitMagicLen = len(kitMagic)
	kitSaltLen  = 16
	kitNonceLen = 12
	kitKeyLen   = 32
	// Iteration count picked so a passphrase guess takes ~50 ms on a 2024-era
	// laptop — enough to make offline brute force expensive while not being
	// painful for the legitimate decrypt path.
	kitDefaultIters = 200_000
)

// generateKitPassphrase returns 32 cryptographically random bytes encoded as
// url-safe base64 (no padding). Result is ~43 ASCII characters, ~256 bits of
// entropy. The string is safe to print to a file (no shell-special chars).
func generateKitPassphrase() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// encryptRecoveryKit produces the ciphertext blob defined by the file
// format above. ``passphrase`` is whatever string the operator supplies
// (random or human-chosen).
func encryptRecoveryKit(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, kitSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	nonce := make([]byte, kitNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	key := pbkdf2.Key([]byte(passphrase), salt, kitDefaultIters, kitKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init gcm: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	var out []byte
	out = append(out, []byte(kitMagic)...)
	out = binary.BigEndian.AppendUint32(out, kitDefaultIters)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// decryptRecoveryKit reverses encryptRecoveryKit. Used by tests (round-trip)
// and by the planned `secrevo import --recovery-kit` command.
func decryptRecoveryKit(blob []byte, passphrase string) ([]byte, error) {
	headerLen := kitMagicLen + 4 + kitSaltLen + kitNonceLen
	if len(blob) < headerLen+16 { // 16 = GCM tag
		return nil, errors.New("recovery kit: blob too small")
	}
	if string(blob[:kitMagicLen]) != kitMagic {
		return nil, errors.New("recovery kit: bad magic (not a Secrevo recovery kit)")
	}
	iters := binary.BigEndian.Uint32(blob[kitMagicLen : kitMagicLen+4])
	if iters < 10_000 || iters > 10_000_000 {
		return nil, fmt.Errorf("recovery kit: implausible iteration count %d", iters)
	}
	saltStart := kitMagicLen + 4
	nonceStart := saltStart + kitSaltLen
	ctStart := nonceStart + kitNonceLen
	salt := blob[saltStart:nonceStart]
	nonce := blob[nonceStart:ctStart]
	ciphertext := blob[ctStart:]

	key := pbkdf2.Key([]byte(passphrase), salt, int(iters), kitKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init gcm: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w (wrong passphrase, corrupted file, or tampered)", err)
	}
	return plaintext, nil
}
