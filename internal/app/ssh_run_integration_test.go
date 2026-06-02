//go:build integration && !windows

package app

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
)

// TestSSHRunPosixIntegrationSpawnsAgent exercises the real posixSSHRunner
// against the real ssh-agent + ssh-add binaries. It is gated behind the
// `integration` build tag so the default `go test` doesn't require ssh
// tooling. Run with:
//
//	go test -tags=integration ./internal/app -run TestSSHRunPosix
//
// The test loads a fresh throwaway ed25519 key (generated in memory via
// ssh-keygen), runs `ssh-add -l` as the child to confirm the agent saw it,
// and lets the deferred SIGTERM tear the agent down.
func TestSSHRunPosixIntegrationSpawnsAgent(t *testing.T) {
	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent not in PATH")
	}
	if _, err := exec.LookPath("ssh-add"); err != nil {
		t.Skip("ssh-add not in PATH")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not in PATH")
	}

	keyPEM, err := generateThrowawayEd25519Key(t)
	if err != nil {
		t.Fatalf("generate throwaway key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	runner := posixSSHRunner{}
	err = runner.Run(context.Background(), sshRunSpec{
		KeyName:  "ITEST_KEY",
		KeyValue: keyPEM,
		Command:  "ssh-add",
		Args:     []string{"-l"},
		Stdout:   &stdout,
		Stderr:   &stderr,
	})
	if err != nil {
		t.Fatalf("Run error = %v (stderr: %s)", err, stderr.String())
	}
	// `ssh-add -l` prints "<bits> <fingerprint> <comment> (ED25519)" when at
	// least one identity is loaded. We only check that *some* identity is
	// listed — fingerprint values intentionally not asserted.
	if got := stdout.String(); got == "" {
		t.Fatalf("ssh-add -l produced no output; agent appears empty")
	}
}

func generateThrowawayEd25519Key(t *testing.T) (string, error) {
	t.Helper()
	dir := t.TempDir()
	out := dir + "/id_ed25519"
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", out, "-q")
	if err := cmd.Run(); err != nil {
		return "", err
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
