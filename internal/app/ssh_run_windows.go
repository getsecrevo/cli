//go:build windows

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

func init() {
	defaultSSHRunner = windowsSSHRunner{}
}

// windowsSSHRunner relies on the persistent OpenSSH ssh-agent service. Win10+
// ships ssh-agent as a service that brokers requests over a named pipe; we
// can't spawn a transient agent the way POSIX does. The trade-off:
//
//  1. Required: the service must already be running. ssh-add talks to it
//     over the named pipe regardless of SSH_AUTH_SOCK.
//  2. The key we add persists for the service's lifetime. To avoid leaking
//     it across runs we drop the same key with `ssh-add -d -` on exit.
//  3. The drop is best-effort: if it fails (service stopped mid-run, key
//     went stale, etc.) we log a warning to stderr but still let the parent
//     exit cleanly.
type windowsSSHRunner struct{}

func (windowsSSHRunner) Run(ctx context.Context, spec sshRunSpec) error {
	if err := requireSSHAgentService(ctx); err != nil {
		return err
	}
	if _, err := exec.LookPath("ssh-add.exe"); err != nil {
		return fmt.Errorf("ssh-add.exe not found in PATH (install OpenSSH client via Settings > Apps > Optional features): %w", err)
	}

	if err := windowsSSHAddKey(ctx, spec.KeyValue); err != nil {
		return fmt.Errorf("load ssh key %q into agent: %w", spec.KeyName, err)
	}
	defer windowsSSHRemoveKey(ctx, spec.KeyValue, spec.Stderr)

	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Env = os.Environ()
	cmd.Stdin = spec.Stdin
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("run %s: %w", spec.Command, err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	done := make(chan struct{})
	go forwardSignals(cmd.Process, ctx, sigCh, done)

	waitErr := cmd.Wait()
	close(done)

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return cliExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("run %s: %w", spec.Command, waitErr)
	}
	return nil
}

// requireSSHAgentService confirms the OpenSSH ssh-agent service is in the
// `Running` state. PowerShell is the most portable way to query it (sc.exe
// output is harder to parse and Get-Service works on every supported Win10+
// release without admin rights).
func requireSSHAgentService(ctx context.Context) error {
	out, err := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoProfile",
		"-Command",
		"Get-Service ssh-agent | Select-Object -ExpandProperty Status",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"OpenSSH ssh-agent service not available (%w). Start it with: "+
				"Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent",
			err,
		)
	}
	status := strings.TrimSpace(string(out))
	if !strings.EqualFold(status, "Running") {
		return fmt.Errorf(
			"OpenSSH ssh-agent service is %q, not Running. Start it with: "+
				"Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent",
			status,
		)
	}
	return nil
}

func windowsSSHAddKey(ctx context.Context, keyValue string) error {
	cmd := exec.CommandContext(ctx, "ssh-add", "-")
	cmd.Stdin = strings.NewReader(ensureTrailingNewlineWindows(keyValue))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return err
		}
		return fmt.Errorf("%s: %w", msg, err)
	}
	return nil
}

// windowsSSHRemoveKey drops the key we added so it doesn't outlive the
// child command in the long-running ssh-agent service. `ssh-add -d -` reads
// the same key bytes from stdin and removes the matching identity. Errors
// are reported to stderr but do not block the parent's exit.
func windowsSSHRemoveKey(ctx context.Context, keyValue string, stderrWriter interface {
	Write(p []byte) (int, error)
}) {
	cmd := exec.CommandContext(ctx, "ssh-add", "-d", "-")
	cmd.Stdin = strings.NewReader(ensureTrailingNewlineWindows(keyValue))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if stderrWriter != nil {
			_, _ = fmt.Fprintf(stderrWriter, "warning: ssh-add -d failed: %s\n", msg)
		}
	}
}

func ensureTrailingNewlineWindows(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
