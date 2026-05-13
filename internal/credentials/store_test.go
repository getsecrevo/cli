package credentials

import (
	"path/filepath"
	"testing"
)

func TestSaveAndLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")

	want := File{
		BaseURL:     "https://api.secrevo.com",
		WorkspaceID: "workspace-1",
		Token:       "agt_secret",
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.BaseURL != want.BaseURL || got.WorkspaceID != want.WorkspaceID || got.Token != want.Token {
		t.Fatalf("loaded = %+v, want %+v", got, want)
	}
	if got.Version != 1 {
		t.Fatalf("version = %d, want 1", got.Version)
	}
}

func TestLoadMissingReturnsErrNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent.json")
	if _, err := Load(path); err != ErrNotFound {
		t.Fatalf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestSaveRefusesEmptyToken(t *testing.T) {
	dir := t.TempDir()
	if err := Save(filepath.Join(dir, "cred.json"), File{}); err == nil {
		t.Fatalf("Save() with empty token should fail")
	}
}

func TestDefaultPathHonorsSecrevoConfigHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SECREVO_CONFIG_HOME", dir)

	got, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath() error = %v", err)
	}
	want := filepath.Join(dir, "credentials.json")
	if got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	if err := Delete(path); err != nil {
		t.Fatalf("Delete() on missing file should be nil, got %v", err)
	}
	if err := Save(path, File{Token: "x"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := Delete(path); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := Load(path); err != ErrNotFound {
		t.Fatalf("after Delete, Load = %v want ErrNotFound", err)
	}
}
