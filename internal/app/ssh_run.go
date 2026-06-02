package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// secretRevealer is the minimal slice of APIClient that ssh-run needs.
// Tests fake this directly without standing up the full APIClient surface.
type secretRevealer interface {
	RevealSecretValueByName(ctx context.Context, workspaceID, name string) (revealedValue, error)
}

// revealedValue mirrors the shape of client.SecretValue but is local to the
// app package so tests don't need to import the client package.
type revealedValue struct {
	Value string
}

// apiSecretRevealer adapts an APIClient to the secretRevealer interface
// expected by the ssh-run platform implementations.
type apiSecretRevealer struct {
	api APIClient
}

func (a apiSecretRevealer) RevealSecretValueByName(ctx context.Context, workspaceID, name string) (revealedValue, error) {
	v, err := a.api.RevealSecretValueByName(ctx, workspaceID, name, "")
	if err != nil {
		return revealedValue{}, err
	}
	return revealedValue{Value: v.Value}, nil
}

// sshRunSpec is the data the platform implementation needs to spawn the
// child after staging the ssh-agent. Stdin/Stdout/Stderr are wired straight
// through to the child.
type sshRunSpec struct {
	KeyName  string
	KeyValue string
	Command  string
	Args     []string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
}

// sshRunner abstracts the POSIX-vs-Windows agent staging + child exec so the
// cobra wiring stays platform-neutral and tests can fake the whole motion.
type sshRunner interface {
	Run(ctx context.Context, spec sshRunSpec) error
}

// defaultSSHRunner is set per-platform in ssh_run_unix.go and
// ssh_run_windows.go. Production wiring defers to it when opts.SSHRunner is
// nil; tests inject their own.
var defaultSSHRunner sshRunner

func newSSHRunCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh-run --key NAME -- <ssh-command> [args...]",
		Short: "Run an SSH command with a key loaded into a transient ssh-agent",
		Long: `Run a child command with a transient ssh-agent that holds one private
key loaded from a Secrevo secret. The key value is fetched in-memory and
piped to ssh-add over stdin — it never lands on disk in this command.

The child sees SSH_AUTH_SOCK pointing at the agent (POSIX) or inherits
the Windows OpenSSH agent service. On exit, POSIX kills the agent
(SIGTERM, then SIGKILL fallback) so the key is wiped from memory;
Windows asks the persistent service to drop only the key we added.

The named secret must hold the private key as a normal string secret
(the same format ssh-add reads from stdin). Storing keys as file-kind
secrets is a separate roadmap item — when it ships, ssh-run will accept
both transparently.

Examples:

  # Forward a Postgres tunnel through a bastion host:
  secrevo ssh-run --key BASTION_KEY -- ssh -N -L 5432:127.0.0.1:5432 \
      odoo@cliente.odoo.com

  # Copy a build artifact to a release host:
  secrevo ssh-run --key DEPLOY_KEY -- \
      scp ./release.tgz deploy@build.example.com:/srv/releases/

  # Run an Ansible playbook over SSH with the loaded key:
  secrevo ssh-run --key OPS_KEY -- ansible-playbook -i hosts site.yml
`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSSHRun(cmd, opts, args)
		},
	}
	cmd.Flags().String("key", "", "Secrevo secret name that holds the SSH private key (required)")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func runSSHRun(cmd *cobra.Command, opts Options, args []string) error {
	workspaceID, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	keyName, _ := cmd.Flags().GetString("key")
	keyName = strings.TrimSpace(keyName)
	if keyName == "" {
		return fmt.Errorf("--key is required and must be a non-empty secret name")
	}

	api, err := getClient(opts)
	if err != nil {
		return err
	}

	revealer := opts.SecretRevealer
	if revealer == nil {
		revealer = apiSecretRevealer{api: api}
	}

	revealed, err := revealer.RevealSecretValueByName(cmd.Context(), workspaceID, keyName)
	if err != nil {
		return fmt.Errorf("reveal secret %q: %w", keyName, err)
	}
	if revealed.Value == "" {
		return fmt.Errorf("secret %q is empty; refusing to load an empty key into ssh-agent", keyName)
	}

	runner := opts.SSHRunner
	if runner == nil {
		runner = defaultSSHRunner
	}
	if runner == nil {
		return fmt.Errorf("ssh-run is not available on this platform")
	}

	stdin := opts.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}

	return runner.Run(cmd.Context(), sshRunSpec{
		KeyName:  keyName,
		KeyValue: revealed.Value,
		Command:  args[0],
		Args:     args[1:],
		Stdin:    stdin,
		Stdout:   opts.Out,
		Stderr:   opts.Err,
	})
}
