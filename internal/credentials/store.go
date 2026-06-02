// Package credentials persists the agent token (and the API base URL +
// workspace id used to mint it) to disk so the CLI can be invoked from a
// fresh shell without re-exporting environment variables every time.
//
// The on-disk format is JSON with a `version` field for forward
// compatibility. Permissions are 0600 on POSIX; on Windows the file is
// written with the inherited ACL — operators concerned about that should
// keep `%APPDATA%` private to their account (which is the default).
//
// On Windows the JSON payload is additionally wrapped with DPAPI
// (`CryptProtectData`, scope `CurrentUser`) so a different user profile
// on the same machine cannot decrypt the file even if they can read it.
// The on-disk layout in that case is the literal 8-byte magic header
// `SECREVO\x01` followed by the DPAPI ciphertext. Files written by
// previous versions of the CLI (plain JSON, no header) load unchanged
// and are transparently re-encrypted on the next Save.
//
// Discovery order, top-to-bottom:
//  1. “SECREVO_CONFIG_HOME/credentials.json“ if SECREVO_CONFIG_HOME is set.
//  2. “$XDG_CONFIG_HOME/secrevo/credentials.json“ on POSIX.
//  3. “~/.config/secrevo/credentials.json“ as the POSIX fallback.
//  4. “%APPDATA%\secrevo\credentials.json“ on Windows.
package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrNotFound is returned by Load when the credentials file does not exist.
// Callers should treat this as "no stored login" rather than an actual error.
var ErrNotFound = errors.New("credentials file does not exist")

// magic is the 8-byte header that prefixes a DPAPI-wrapped payload on
// Windows. Files lacking this header are treated as legacy plain JSON.
var magic = []byte{'S', 'E', 'C', 'R', 'E', 'V', 'O', 0x01}

// File is the on-disk representation.
type File struct {
	Version     int    `json:"version"`
	BaseURL     string `json:"base_url"`
	WorkspaceID string `json:"workspace_id"`
	Token       string `json:"token"`
}

// DefaultPath returns the path the CLI will read/write credentials to,
// honoring SECREVO_CONFIG_HOME, XDG_CONFIG_HOME, and falling back to the
// platform-specific user config root.
func DefaultPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv("SECREVO_CONFIG_HOME")); override != "" {
		return filepath.Join(override, "credentials.json"), nil
	}
	if runtime.GOOS == "windows" {
		appdata := strings.TrimSpace(os.Getenv("APPDATA"))
		if appdata == "" {
			return "", errors.New("APPDATA is not set; cannot resolve credentials path")
		}
		return filepath.Join(appdata, "secrevo", "credentials.json"), nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "secrevo", "credentials.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".config", "secrevo", "credentials.json"), nil
}

// Load reads the credentials file from “path“. If the file does not
// exist, returns ErrNotFound; the caller decides whether that is fatal.
//
// On Windows, files starting with the SECREVO\x01 magic header are
// DPAPI-unprotected before JSON parsing. Files without the header (or
// shorter than the header) are treated as legacy plain JSON; the next
// Save call will write them back wrapped.
func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return File{}, ErrNotFound
		}
		return File{}, fmt.Errorf("read %s: %w", path, err)
	}
	payload := data
	if len(data) >= len(magic) && bytes.Equal(data[:len(magic)], magic) {
		plain, err := unprotect(data[len(magic):])
		if err != nil {
			return File{}, fmt.Errorf("unprotect %s: %w", path, err)
		}
		payload = plain
	}
	var f File
	if err := json.Unmarshal(payload, &f); err != nil {
		return File{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.Version != 1 {
		return File{}, fmt.Errorf("unsupported credentials version %d in %s", f.Version, path)
	}
	return f, nil
}

// Save writes the credentials file with mode 0600 (POSIX). Parent
// directories are created as needed.
//
// On Windows the JSON payload is wrapped with DPAPI (scope CurrentUser)
// and prefixed with the SECREVO\x01 magic header before being written
// to disk. On POSIX the file is plain JSON.
func Save(path string, f File) error {
	f.Version = 1
	if strings.TrimSpace(f.Token) == "" {
		return errors.New("token cannot be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	payload, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	ciphertext, wrapped, err := protect(payload)
	if err != nil {
		return fmt.Errorf("protect credentials: %w", err)
	}
	var body []byte
	if wrapped {
		body = make([]byte, 0, len(magic)+len(ciphertext))
		body = append(body, magic...)
		body = append(body, ciphertext...)
	} else {
		// POSIX identity path: emit plain JSON.
		body = ciphertext
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// Delete removes the credentials file. Returns nil if the file does not
// exist (mirrors `secrevo logout` semantics).
func Delete(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}
