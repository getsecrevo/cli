//go:build !windows

package credentials

// protect is the identity transform on non-Windows platforms. The
// returned `wrapped` flag is false, so Save will emit plain JSON
// (which matches the `chmod 0600` protection contract the package
// has always offered on POSIX).
func protect(plaintext []byte) (out []byte, wrapped bool, err error) {
	return plaintext, false, nil
}

// unprotect is the identity inverse. On non-Windows platforms a
// magic-prefixed file should not occur (Save never writes the header
// here); if it ever does — e.g. a credentials file synced from a
// Windows host — return the bytes as-is and let the JSON parser
// surface the corruption.
func unprotect(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}
