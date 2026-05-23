//go:build windows

package credentials

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protect wraps `plaintext` with DPAPI at scope CurrentUser. The
// resulting ciphertext is opaque and tied to the current user profile —
// any other Windows account on the same machine will fail to
// unprotect it, even with read access to the credentials file.
//
// CRYPTPROTECT_UI_FORBIDDEN: never display a UI (CLI must remain
// non-interactive). entropy is nil — DPAPI's per-user master key is
// the sole secret. CRYPTPROTECT_LOCAL_MACHINE is deliberately NOT
// set, so the scope stays CurrentUser.
func protect(plaintext []byte) (out []byte, wrapped bool, err error) {
	in := toBlob(plaintext)
	var cipher windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &cipher); err != nil {
		return nil, false, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer freeBlob(&cipher)
	return cloneBlob(&cipher), true, nil
}

// unprotect reverses protect. Fails with the underlying DPAPI error
// (typically `The data is invalid` / 0x8007000D when the file was
// encrypted under a different user profile, or `Key not valid for use
// in specified state` when the user master key has been reset).
func unprotect(ciphertext []byte) ([]byte, error) {
	in := toBlob(ciphertext)
	var plain windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &plain); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer freeBlob(&plain)
	return cloneBlob(&plain), nil
}

// toBlob wraps a Go byte slice in a DataBlob suitable for the DPAPI
// syscalls. The returned blob aliases the slice's backing array, so
// the caller must keep `b` alive for the duration of the call.
func toBlob(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{Size: 0, Data: nil}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// cloneBlob copies the contents of a DPAPI-allocated DataBlob into a
// Go-owned []byte. The caller is responsible for freeing the original
// blob's memory via freeBlob.
func cloneBlob(b *windows.DataBlob) []byte {
	if b == nil || b.Size == 0 || b.Data == nil {
		return nil
	}
	src := unsafe.Slice(b.Data, int(b.Size))
	out := make([]byte, b.Size)
	copy(out, src)
	return out
}

// freeBlob releases the LocalAlloc'd buffer DPAPI returned. Errors are
// intentionally swallowed: there is nothing actionable to do if
// LocalFree fails at this layer.
func freeBlob(b *windows.DataBlob) {
	if b == nil || b.Data == nil {
		return
	}
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
}
