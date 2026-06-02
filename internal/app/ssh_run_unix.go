//go:build !windows

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func init() {
	defaultSSHRunner = posixSSHRunner{}
}

// posixSSHRunner spawns a fresh ssh-agent for the duration of the child
// command, loads exactly one key into it from stdin, then tears the agent
// down with SIGTERM (SIGKILL fallback) so the key is wiped from memory.
type posixSSHRunner struct{}

func (posixSSHRunner) Run(ctx context.Context, spec sshRunSpec) error {
	sock, agentPID, err := spawnSSHAgent(ctx)
	if err != nil {
		return fmt.Errorf("spawn ssh-agent: %w", err)
	}
	defer killSSHAgent(agentPID)

	if err := sshAddKey(ctx, sock, spec.KeyValue); err != nil {
		return fmt.Errorf("load ssh key %q into agent: %w", spec.KeyName, err)
	}

	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	cmd.Stdin = spec.Stdin
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("run %s: %w", spec.Command, err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
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

// spawnSSHAgent runs `ssh-agent -s` and parses its Bourne-style output for
// the SSH_AUTH_SOCK and SSH_AGENT_PID values. Output shape (per OpenSSH
// ssh-agent(1)):
//
//	SSH_AUTH_SOCK=/tmp/ssh-XYZ/agent.123; export SSH_AUTH_SOCK;
//	SSH_AGENT_PID=124; export SSH_AGENT_PID;
//	echo Agent pid 124;
func spawnSSHAgent(ctx context.Context) (string, int, error) {
	cmd := exec.CommandContext(ctx, "ssh-agent", "-s")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("ssh-agent -s: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	sock := parseAgentEnv(stdout.String(), "SSH_AUTH_SOCK")
	pidStr := parseAgentEnv(stdout.String(), "SSH_AGENT_PID")
	if sock == "" {
		return "", 0, fmt.Errorf("ssh-agent did not advertise SSH_AUTH_SOCK in its stdout")
	}
	if pidStr == "" {
		return "", 0, fmt.Errorf("ssh-agent did not advertise SSH_AGENT_PID in its stdout")
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return "", 0, fmt.Errorf("parse SSH_AGENT_PID %q: %w", pidStr, err)
	}
	return sock, pid, nil
}

// parseAgentEnv pulls the value for `KEY=` from ssh-agent's `KEY=value;
// export KEY;` lines. Returns "" if not found.
func parseAgentEnv(output, key string) string {
	prefix := key + "="
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimPrefix(line, prefix)
		if i := strings.Index(rest, ";"); i >= 0 {
			rest = rest[:i]
		}
		return strings.TrimSpace(rest)
	}
	return ""
}

// sshAddKey pipes the key bytes into `ssh-add -` against the freshly spawned
// agent. ssh-add reads stdin until EOF and treats the contents as the
// private key body, identical to `ssh-add /path/to/key` but without a disk
// write.
func sshAddKey(ctx context.Context, sock, keyValue string) error {
	cmd := exec.CommandContext(ctx, "ssh-add", "-")
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	cmd.Stdin = strings.NewReader(ensureTrailingNewline(keyValue))
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

// ensureTrailingNewline guards against an OpenSSH parser quirk: keys read
// from stdin must end with a newline or ssh-add reports "error loading key
// (Invalid format)". A no-op when the value already ends with one.
func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// killSSHAgent tears the transient agent down. SIGTERM gives it a chance to
// wipe its memory cleanly; SIGKILL is the fallback if it doesn't exit within
// ~500ms. Errors are swallowed because the agent may already have exited
// when its parent's defer fires.
func killSSHAgent(pid int) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = proc.Signal(syscall.SIGTERM)

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			// Process is gone.
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = proc.Kill()
}
