package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/getsecrevo/cli/internal/client"
	"github.com/getsecrevo/cli/internal/credentials"
	"github.com/spf13/cobra"
)

// mustCompileGraceRe compiles the grace-window regex at package init.
// Kept as a function so the regex literal is visible to readers without
// a global init() block.
func mustCompileGraceRe() *regexp.Regexp {
	return regexp.MustCompile(`^[1-9][0-9]*(h|m|s)$`)
}

// defaultVersion is overridden at build time via
// `-ldflags '-X github.com/getsecrevo/cli/internal/app.defaultVersion=v0.X.Y'`
// from the release workflow (goreleaser). Local `go build` keeps the
// `-dev` suffix.
var defaultVersion = "0.1.0-dev"

type APIClient interface {
	BaseURL() string
	Whoami(context.Context) (client.Session, error)
	BootstrapWorkspace(context.Context, client.BootstrapWorkspaceRequest) (client.BootstrapWorkspaceResponse, error)
	ListSecrets(context.Context, string) (client.SecretListResponse, error)
	GetSecret(context.Context, string, string) (client.Secret, error)
	RevealSecretValue(context.Context, string, string) (client.SecretValue, error)
	RevealSecretValueByName(context.Context, string, string, string) (client.SecretValue, error)
	CreateSecret(context.Context, string, client.SecretCreateRequest) (client.Secret, error)
	RotateSecretValue(context.Context, string, string, string, string) error
	UpdateSecret(context.Context, string, string, client.SecretUpdateRequest) (client.Secret, error)
	DeleteSecret(context.Context, string, string) error
	CreateAgent(context.Context, string, client.AgentCreateRequest) (client.AgentCreateResponse, error)
	ProxyConsume(context.Context, string, string, client.ProxyRequest) (client.ProxyResponse, error)
	OpenProxySession(context.Context, string, string) (client.ProxySession, error)
	ProxySessionConsume(context.Context, string, string, client.ProxyRequest) (client.ProxyResponse, error)
	CloseProxySession(context.Context, string, string) error
	ListProxyTargets(context.Context, string, string) ([]client.ProxyTarget, error)
	PutProxyTarget(context.Context, string, string, client.ProxyTarget) (client.ProxyTarget, error)
	DeleteProxyTarget(context.Context, string, string, string) error
	MintCreds(context.Context, string, string, int) (client.Cred, error)
	GetCredScope(context.Context, string, string) (client.CredScope, error)
	PutCredScope(context.Context, string, string, client.CredScope) (client.CredScope, error)
	DeleteCredScope(context.Context, string, string) error
}

type Options struct {
	Version       string
	WorkspaceID   string
	ClientFactory func() (APIClient, error)
	Out           io.Writer
	Err           io.Writer
	// Runner is the side-effecting subprocess executor used by `secrevo run`.
	// Tests inject a fake; production wiring leaves it nil to use the
	// os/exec-backed default.
	Runner Runner
	// Stdin is used as the child process stdin in `secrevo run`. Leaving
	// it nil falls back to os.Stdin in production and io.Reader-based test
	// fakes inject their own.
	Stdin io.Reader
	// Browser opens a URL during `secrevo login`. Tests inject a no-op
	// fake; production uses the OS default browser.
	Browser BrowserOpener
	// LoginVerifier validates a captured agent token before persisting it.
	// Tests inject a func that returns nil; production posts to
	// /v1/auth/sessions.
	LoginVerifier func(ctx context.Context, baseURL, token string) error
	// CredentialsPath overrides the on-disk credentials file location.
	// Tests inject a temp path; production uses credentials.DefaultPath().
	CredentialsPath string
	// SSHRunner is the side-effecting executor used by `secrevo ssh-run`.
	// Tests inject a fake; production wiring leaves it nil so the per-platform
	// default (defaultSSHRunner in ssh_run_{unix,windows}.go) is used.
	SSHRunner sshRunner
	// SecretRevealer overrides the by-name reveal used by `secrevo ssh-run`.
	// Tests inject a fake to assert reveal failures don't spawn ssh-agent;
	// production leaves it nil so the APIClient is used directly.
	SecretRevealer secretRevealer
	// EnrollPoster overrides the HTTP edge used by `secrevo enroll`.
	// Tests inject a fake backed by httptest; production leaves it nil so
	// defaultEnrollPoster posts directly to /v1/enrollment/redeem.
	EnrollPoster enrollPoster
}

func Execute(args []string, out, errOut io.Writer) error {
	workspaceID := strings.TrimSpace(os.Getenv("SECREVO_WORKSPACE_ID"))
	if workspaceID == "" {
		// Fall back to the workspace recorded by `secrevo login` so
		// commands that need --workspace-id don't error out when the
		// operator authenticated via the CLI.
		if path, err := credentials.DefaultPath(); err == nil {
			if stored, err := credentials.Load(path); err == nil {
				workspaceID = strings.TrimSpace(stored.WorkspaceID)
			}
		}
	}
	opts := Options{
		Version:     defaultVersion,
		WorkspaceID: workspaceID,
		Out:         out,
		Err:         errOut,
		ClientFactory: func() (APIClient, error) {
			return client.NewFromEnv()
		},
	}

	cmd := NewRootCommand(opts)
	cmd.SetArgs(args)
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	return cmd.Execute()
}

func NewRootCommand(opts Options) *cobra.Command {
	if opts.Version == "" {
		opts.Version = defaultVersion
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Err == nil {
		opts.Err = io.Discard
	}
	if opts.ClientFactory == nil {
		opts.ClientFactory = func() (APIClient, error) {
			return client.NewFromEnv()
		}
	}

	root := &cobra.Command{
		Use:              "secrevo",
		Short:            "Secrevo CLI",
		SilenceUsage:     true,
		SilenceErrors:    true,
		TraverseChildren: true,
	}
	root.SetOut(opts.Out)
	root.SetErr(opts.Err)
	root.PersistentFlags().String("workspace-id", opts.WorkspaceID, "Workspace ID (or SECREVO_WORKSPACE_ID)")

	root.AddCommand(newVersionCommand(opts))
	root.AddCommand(newAuthCommand(opts))
	root.AddCommand(newWorkspaceCommand(opts))
	root.AddCommand(newSecretCommand(opts))
	root.AddCommand(newAgentCommand(opts))
	root.AddCommand(newRunCommand(opts))
	root.AddCommand(newCallCommand(opts))
	root.AddCommand(newSessionCommand(opts))
	root.AddCommand(newCredsCommand(opts))
	root.AddCommand(newSSHRunCommand(opts))
	root.AddCommand(newImportCommand(opts))
	root.AddCommand(newEnvCommand(opts))
	root.AddCommand(newExportCommand(opts))
	root.AddCommand(newLoginCommand(opts))
	root.AddCommand(newLogoutCommand(opts))
	root.AddCommand(newEnrollCommand(opts))

	return root
}

func newVersionCommand(opts Options) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CLI version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintln(opts.Out, opts.Version)
			return err
		},
	}
}

func newAuthCommand(opts Options) *cobra.Command {
	auth := &cobra.Command{
		Use:   "auth",
		Short: "Authentication commands",
	}
	auth.AddCommand(&cobra.Command{
		Use:   "whoami",
		Short: "Show the current Prysm:ID session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(opts, func(api APIClient) error {
				session, err := api.Whoami(cmd.Context())
				if err != nil {
					return err
				}
				return writeJSON(opts.Out, session)
			})
		},
	})
	return auth
}

func newWorkspaceCommand(opts Options) *cobra.Command {
	workspace := &cobra.Command{
		Use:   "workspace",
		Short: "Workspace commands",
	}
	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap a workspace",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			adminEmail, _ := cmd.Flags().GetString("admin-email")
			return withClient(opts, func(api APIClient) error {
				resp, err := api.BootstrapWorkspace(cmd.Context(), client.BootstrapWorkspaceRequest{
					Name:       strings.TrimSpace(name),
					AdminEmail: strings.TrimSpace(adminEmail),
				})
				if err != nil {
					return err
				}
				return writeJSON(opts.Out, resp)
			})
		},
	}
	bootstrap.Flags().String("name", "", "Optional workspace name")
	bootstrap.Flags().String("admin-email", "", "Optional admin email")
	workspace.AddCommand(bootstrap)
	return workspace
}

func newSecretCommand(opts Options) *cobra.Command {
	secret := &cobra.Command{
		Use:   "secret",
		Short: "Secret commands",
	}
	secret.AddCommand(&cobra.Command{
		Use:   "get <secret-name>",
		Short: "Fetch secret metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceID, err := workspaceID(cmd)
			if err != nil {
				return err
			}
			return withClient(opts, func(api APIClient) error {
				list, err := api.ListSecrets(cmd.Context(), workspaceID)
				if err != nil {
					return err
				}
				secretID, err := resolveSecretID(list.Secrets, args[0])
				if err != nil {
					return err
				}
				resp, err := api.GetSecret(cmd.Context(), workspaceID, secretID)
				if err != nil {
					return err
				}
				return writeJSON(opts.Out, resp)
			})
		},
	})
	secret.AddCommand(newSecretListCommand(opts))
	secret.AddCommand(newSecretSetCommand(opts))
	secret.AddCommand(newSecretUpdateCommand(opts))
	secret.AddCommand(newSecretRenameCommand(opts))
	secret.AddCommand(newSecretEditCommand(opts))
	secret.AddCommand(newSecretDeleteCommand(opts))
	secret.AddCommand(newSecretRevealCommand(opts))
	secret.AddCommand(newSecretProxyTargetCommand(opts))
	secret.AddCommand(newSecretCredScopeCommand(opts))
	return secret
}

func newSecretRevealCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reveal <secret-name>",
		Short: "Reveal a secret's value (one-off; for scripts prefer `run`/`env --secret`)",
		Long: `Reveal a secret's value. Intended for interactive one-off lookups —
for scripts that feed a value to a process, ` + "`secrevo run --secret`" + ` or
` + "`secrevo env --secret`" + ` are safer (no value ever lands in the shell
history or a logged transcript).

The value source must be exactly one destination:

  --allow-stdout            Print the value to stdout (mandatory consent).
  --to-file PATH            Write the value to PATH (POSIX: chmod 0600) and
                            print nothing.

` + "`--allow-stdout`" + ` is mandatory when stdout is the destination — without it
the command refuses to print the value and prints an actionable error
pointing at the two safe alternatives. Pair it with ` + "`--json`" + ` to emit a
` + "`{value, secret_id, workspace_id}`" + ` envelope instead of the bare value
(useful when consuming from a structured wrapper).

Every reveal is recorded in the workspace audit log under
` + "`secret.read`" + `; the value is unrecoverable from the API.

Examples:

  secrevo secret reveal OPENAI_API_KEY --allow-stdout
  secrevo secret reveal OPENAI_API_KEY --allow-stdout --json
  secrevo secret reveal SSH_KEY --to-file ./id_ed25519
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretReveal(cmd, opts, args[0])
		},
	}
	cmd.Flags().Bool("allow-stdout", false, "Print the value to stdout (required when --to-file is not set)")
	cmd.Flags().Bool("json", false, "With --allow-stdout, emit {value, secret_id, workspace_id} as JSON instead of the bare value")
	cmd.Flags().String("to-file", "", "Write the value to PATH (POSIX: chmod 0600) and print nothing")
	cmd.Flags().String("version", "current", "Which value to read: 'current' (live) or 'previous' (the snapshot from a `--grace` rotation, if still in window). Scripted commands like `run`/`env --secret` always read 'current'; reading 'previous' is a one-off operator action.")
	return cmd
}

func runSecretReveal(cmd *cobra.Command, opts Options, name string) error {
	workspaceID, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	allowStdout, _ := cmd.Flags().GetBool("allow-stdout")
	asJSON, _ := cmd.Flags().GetBool("json")
	toFile, _ := cmd.Flags().GetString("to-file")
	version, _ := cmd.Flags().GetString("version")

	if toFile != "" && allowStdout {
		return fmt.Errorf("--to-file and --allow-stdout are mutually exclusive: pick one destination")
	}
	if toFile == "" && !allowStdout {
		return fmt.Errorf(
			"refusing to print secret %q to stdout without explicit consent.\n"+
				"  Pass --allow-stdout to confirm, or use --to-file PATH to materialize without printing.\n"+
				"  Either way the reveal is recorded in the workspace audit log under \"secret.read\".",
			name,
		)
	}
	if toFile != "" && asJSON {
		return fmt.Errorf("--json applies only to --allow-stdout output; remove it when using --to-file")
	}
	switch strings.TrimSpace(version) {
	case "", "current", "previous":
	default:
		return fmt.Errorf("--version must be 'current' or 'previous'; got %q", version)
	}

	return withClient(opts, func(api APIClient) error {
		revealed, err := api.RevealSecretValueByName(cmd.Context(), workspaceID, name, version)
		if err != nil {
			if isNotFoundPrevious(err) {
				return fmt.Errorf(
					"No previous value available for %q. Either the rotation was done without --grace, or the grace window expired.",
					name,
				)
			}
			if isForbidden(err) {
				return fmt.Errorf(
					"Not allowed to reveal %q to yourself.\n"+
						"  Displaying a secret's plaintext to a human requires the \"secret.reveal\" capability.\n"+
						"  This access may be agent-only: an agent token can still consume the value at runtime\n"+
						"  (e.g. via `secrevo run`), but human reveal is withheld. Ask a workspace admin to grant\n"+
						"  you \"secret.reveal\" on this secret.",
					name,
				)
			}
			return fmt.Errorf("reveal secret %q: %w", name, err)
		}
		if toFile != "" {
			if err := writeSecretToFile(toFile, revealed.Value, opts); err != nil {
				return err
			}
			if revealed.GraceExpiresAt != "" {
				_, _ = fmt.Fprintf(opts.Err, "(previous value written to %s; grace expires at %s)\n", toFile, revealed.GraceExpiresAt)
			}
			return nil
		}
		if asJSON {
			return writeJSON(opts.Out, revealed)
		}
		if revealed.GraceExpiresAt != "" {
			_, _ = fmt.Fprintf(opts.Err, "(previous value, grace expires at %s)\n", revealed.GraceExpiresAt)
		}
		_, err = fmt.Fprintln(opts.Out, revealed.Value)
		return err
	})
}

// isNotFoundPrevious recognizes the api#46 sentinel returned when the caller
// asked for `?version=previous` but no snapshot is available (rotation
// happened without --grace, or the window expired). The api returns
// 404 with a body containing the token "not_found_previous"; the client
// wraps the body verbatim into the error string.
func isNotFoundPrevious(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "404") && strings.Contains(msg, "not_found_previous")
}

// isForbidden recognizes the api's 403 missing-capability response. The client
// wraps the HTTP status and body verbatim ("api returned 403 Forbidden: ...
// forbidden ..."), so a human reveal blocked for lack of secret.reveal lands
// here and the caller can print an actionable, capability-specific hint instead
// of the raw status line.
func isForbidden(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "403") && strings.Contains(msg, "forbidden")
}

// writeSecretToFile materializes a revealed value at path with restrictive
// permissions. On POSIX the file is created with mode 0600 so a sibling
// process owned by the same user cannot mmap it. On Windows the ACL of the
// containing directory governs access (DPAPI is not in scope here — this
// is a transient materialization, not a credential store). The function
// truncates an existing file at the path; the caller is responsible for
// cleanup.
func writeSecretToFile(path, value string, opts Options) error {
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(opts.Err, "Wrote secret to %s (mode 0600)\n", path)
	return nil
}

func newSecretDeleteCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <secret-name>",
		Short: "Delete a secret and cascade-revoke its scoped grants",
		Long: `Delete a secret from the workspace. The server destroys the OpenBao
value + history and cascade-revokes every grant scoped to this specific
secret. Workspace-wide grants are untouched (they only match a real
authorization when a secret of the same id exists, so they become
effectively dormant for this id).

By default the command refuses to run when stdin is not a TTY without
` + "`--yes`" + ` so scripts cannot accidentally delete a secret without an
explicit confirmation. Interactive sessions get a yes/no prompt that
echoes the secret name back; any answer other than "y" or "yes"
aborts.

The deletion is recorded in the workspace audit log under
` + "`secret.deleted`" + `; the value is unrecoverable from the API.

Examples:

  secrevo secret delete OPENAI_API_KEY            # interactive confirm
  secrevo secret delete OPENAI_API_KEY --yes      # scripted
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretDelete(cmd, opts, args[0])
		},
	}
	cmd.Flags().Bool("yes", false, "Skip the interactive confirmation prompt; required when stdin is not a TTY")
	return cmd
}

func runSecretDelete(cmd *cobra.Command, opts Options, name string) error {
	workspaceID, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	yes, _ := cmd.Flags().GetBool("yes")

	if !yes {
		stdin := opts.Stdin
		if stdin == nil {
			stdin = os.Stdin
		}
		if !isInteractive(stdin) {
			return fmt.Errorf("refusing to delete %q without --yes: stdin is not a TTY", name)
		}
		_, _ = fmt.Fprintf(opts.Err, "Delete secret %q in workspace %s? [y/N]: ", name, workspaceID)
		var answer string
		if _, scanErr := fmt.Fscanln(stdin, &answer); scanErr != nil && !errors.Is(scanErr, io.EOF) {
			return fmt.Errorf("read confirmation: %w", scanErr)
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			return fmt.Errorf("aborted: confirmation not received (got %q)", answer)
		}
	}

	return withClient(opts, func(api APIClient) error {
		list, err := api.ListSecrets(cmd.Context(), workspaceID)
		if err != nil {
			return fmt.Errorf("list secrets: %w", err)
		}
		secretID, err := resolveSecretID(list.Secrets, name)
		if err != nil {
			return err
		}
		if err := api.DeleteSecret(cmd.Context(), workspaceID, secretID); err != nil {
			return fmt.Errorf("delete secret %q: %w", name, err)
		}
		_, _ = fmt.Fprintf(opts.Out, "Deleted secret %q (%s) in workspace %s\n", name, secretID, workspaceID)
		return nil
	})
}

// isInteractive reports whether the reader is a real terminal. It is used
// by `secret delete` to refuse running without --yes in non-interactive
// contexts (CI scripts, piped stdin) so a runaway loop cannot delete a
// secret without an explicit operator gesture. The implementation is
// best-effort: any reader that doesn't expose an *os.File underlying
// descriptor is treated as non-interactive.
func isInteractive(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func newSecretListCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every secret visible to the current token",
		Long: `List secrets in the workspace. The default output is one secret
name per line, sorted alphabetically — convenient for piping to grep or
fzf. Pass --json for the structured array (the same shape ` + "`secrets get`" + `
returns per entry).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceID, err := workspaceID(cmd)
			if err != nil {
				return err
			}
			asJSON, _ := cmd.Flags().GetBool("json")
			return withClient(opts, func(api APIClient) error {
				list, err := api.ListSecrets(cmd.Context(), workspaceID)
				if err != nil {
					return err
				}
				if asJSON {
					return writeJSON(opts.Out, list)
				}
				names := secretNames(list.Secrets)
				sort.Strings(names)
				for _, name := range names {
					_, _ = fmt.Fprintln(opts.Out, name)
				}
				return nil
			})
		},
	}
	cmd.Flags().Bool("json", false, "Emit the full list as JSON instead of one name per line")
	return cmd
}

func newSecretRenameCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <old-name> <new-name>",
		Short: "Rename a secret without touching its value",
		Long: `Rename a secret. The value, audit history, and grants are untouched
— only the metadata name changes. Useful to clean up names imported with
the legacy '.' separator (` + "`aws.cloudwatch.url`" + ` → ` + "`AWS_CLOUDWATCH_URL`" + `) so
they're directly usable in ` + "`secrevo env` / `secrevo run`" + ` without --raw-name.

Pass --sanitize to use the canonical POSIX form of <new-name> (the same
transformation env/run apply by default). With --sanitize, ` + "`<new-name>`" + `
acts as the seed: ` + "`secrevo secret rename aws.cloud.url _ --sanitize`" + ` is a
shorthand for ` + "`secrevo secret rename aws.cloud.url AWS_CLOUD_URL`" + `.

Examples:

  secrevo secret rename aws.cloudwatch.url AWS_CLOUDWATCH_URL
  secrevo secret rename prysmid.idp.google.client_id PRYSMID_GOOGLE_CLIENT_ID
`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceID, err := workspaceID(cmd)
			if err != nil {
				return err
			}
			oldName := args[0]
			newName := args[1]
			doSanitize, _ := cmd.Flags().GetBool("sanitize")
			if doSanitize {
				newName = sanitizeEnvName(oldName)
			}
			if strings.TrimSpace(newName) == "" {
				return fmt.Errorf("new name is empty after sanitization")
			}
			return withClient(opts, func(api APIClient) error {
				list, err := api.ListSecrets(cmd.Context(), workspaceID)
				if err != nil {
					return fmt.Errorf("list secrets: %w", err)
				}
				secretID, err := resolveSecretID(list.Secrets, oldName)
				if err != nil {
					return err
				}
				if existing := findSecretByName(list.Secrets, newName); existing != nil {
					return fmt.Errorf("a secret named %q already exists in workspace %s", newName, workspaceID)
				}
				updated, err := api.UpdateSecret(cmd.Context(), workspaceID, secretID, client.SecretUpdateRequest{Name: &newName})
				if err != nil {
					return fmt.Errorf("rename %q: %w", oldName, err)
				}
				_, _ = fmt.Fprintf(opts.Out, "Renamed %q -> %q (%s) in workspace %s\n", oldName, updated.Name, updated.SecretID, workspaceID)
				return nil
			})
		},
	}
	cmd.Flags().Bool("sanitize", false, "Use the sanitized POSIX form of <old-name>; <new-name> argument is then ignored")
	return cmd
}

func newSecretEditCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <secret-name>",
		Short: "Edit a secret's metadata without touching its value",
		Long: `Edit the metadata of an existing secret. The stored value is NEVER
read, written, or rotated — this issues a metadata-only PATCH, so the
audit log records ` + "`secret.updated`" + ` and not a value rotation.

Only the fields you pass are changed; omitted fields are left exactly as
they were (true partial update). Pass at least one of:

  --description "..."
  --regeneration-instructions "..."        inline text
  --regeneration-instructions-file PATH    read the text from a file (use
                                            '-' to read from stdin), for
                                            multi-line runbooks
  --tag LABEL                               repeatable; REPLACES the entire
                                            tag set (pass --tag with no value
                                            via --clear-tags to remove all)
  --clear-tags                              remove every tag
  --status active|rotating|archived

Examples:

  secrevo secret edit OPENAI_API_KEY --regeneration-instructions "Rotate in the OpenAI dashboard, then secrevo secret set"
  secrevo secret edit DB_PASSWORD --regeneration-instructions-file ./runbooks/db-rotation.md
  cat runbook.md | secrevo secret edit DB_PASSWORD --regeneration-instructions-file -
  secrevo secret edit STRIPE_KEY --tag billing --tag prod
  secrevo secret edit OLD_KEY --status archived
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretEdit(cmd, opts, args[0])
		},
	}
	cmd.Flags().String("description", "", "Set the secret's description")
	cmd.Flags().String("regeneration-instructions", "", "Set the rotation notes (inline text)")
	cmd.Flags().String("regeneration-instructions-file", "", "Read the rotation notes from a file path ('-' for stdin)")
	cmd.Flags().StringArray("tag", nil, "Set a tag; repeat for multiple. Replaces the entire existing tag set")
	cmd.Flags().Bool("clear-tags", false, "Remove all tags from the secret")
	cmd.Flags().String("status", "", "Set the lifecycle status: active, rotating, or archived")
	return cmd
}

func runSecretEdit(cmd *cobra.Command, opts Options, name string) error {
	workspaceID, err := workspaceID(cmd)
	if err != nil {
		return err
	}

	var req client.SecretUpdateRequest

	if cmd.Flags().Changed("description") {
		v, _ := cmd.Flags().GetString("description")
		req.Description = &v
	}

	inlineRegen := cmd.Flags().Changed("regeneration-instructions")
	fileRegen := cmd.Flags().Changed("regeneration-instructions-file")
	if inlineRegen && fileRegen {
		return fmt.Errorf("--regeneration-instructions and --regeneration-instructions-file are mutually exclusive")
	}
	if inlineRegen {
		v, _ := cmd.Flags().GetString("regeneration-instructions")
		req.RegenerationInstructions = &v
	}
	if fileRegen {
		path, _ := cmd.Flags().GetString("regeneration-instructions-file")
		text, err := readRegenerationFile(cmd, opts, path)
		if err != nil {
			return err
		}
		req.RegenerationInstructions = &text
	}

	if cmd.Flags().Changed("status") {
		v, _ := cmd.Flags().GetString("status")
		req.Status = &v
	}

	tagsChanged := cmd.Flags().Changed("tag")
	clearTags, _ := cmd.Flags().GetBool("clear-tags")
	if tagsChanged && clearTags {
		return fmt.Errorf("--tag and --clear-tags are mutually exclusive")
	}
	if clearTags {
		empty := []string{}
		req.Tags = &empty
	} else if tagsChanged {
		tags, _ := cmd.Flags().GetStringArray("tag")
		req.Tags = &tags
	}

	if req.Description == nil && req.RegenerationInstructions == nil && req.Status == nil && req.Tags == nil {
		return fmt.Errorf("nothing to edit: pass at least one of --description, --regeneration-instructions[-file], --tag/--clear-tags, or --status")
	}

	return withClient(opts, func(api APIClient) error {
		list, err := api.ListSecrets(cmd.Context(), workspaceID)
		if err != nil {
			return fmt.Errorf("list secrets: %w", err)
		}
		secretID, err := resolveSecretID(list.Secrets, name)
		if err != nil {
			return err
		}
		updated, err := api.UpdateSecret(cmd.Context(), workspaceID, secretID, req)
		if err != nil {
			return fmt.Errorf("edit secret %q: %w", name, err)
		}
		_, _ = fmt.Fprintf(opts.Out, "Updated metadata for secret %q (%s) in workspace %s\n", updated.Name, updated.SecretID, workspaceID)
		return nil
	})
}

// readRegenerationFile reads rotation notes from a file path, or from stdin
// when path is "-". The content is taken verbatim except for a trailing
// newline strip, so multi-line runbooks survive intact.
func readRegenerationFile(cmd *cobra.Command, opts Options, path string) (string, error) {
	if path == "-" {
		stdin := opts.Stdin
		if stdin == nil {
			stdin = os.Stdin
		}
		data, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

func newSecretSetCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <secret-name>",
		Short: "Create or rotate a secret's value",
		Long: `Create a new secret or rotate the value of an existing one.

If the secret name does not exist in the workspace, it is created with
the supplied value (and optional --description). If it already exists,
its value is rotated and metadata is left untouched — passing
--description or --regeneration-instructions on a rotation is rejected
with an error (use ` + "`secrevo secret edit`" + ` to change metadata only).

Use --update-only to refuse creating a new secret (useful in rotation
scripts that should fail loud if the secret was deleted). Use
--create-only to refuse rotating an existing one.

The value source must be exactly one of:
  --value "literal"
  --from-file PATH    (reads the file as the value, preserving newlines)
  --from-stdin        (reads stdin until EOF)

Examples:

  secrevo secret set OPENAI_API_KEY --value "sk-live-..."
  secrevo secret set CLOUDFLARE_TOKEN --from-file ~/.devvault/cf.txt
  cat secret.key | secrevo secret set RSA_PRIVATE --from-stdin
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretSet(cmd, opts, args[0], false)
		},
	}
	cmd.Flags().String("value", "", "Literal secret value (cannot combine with --from-file/--from-stdin)")
	cmd.Flags().String("from-file", "", "Read the secret value from a file path")
	cmd.Flags().Bool("from-stdin", false, "Read the secret value from stdin until EOF")
	cmd.Flags().String("description", "", "Description, applied only when creating; on an existing secret this errors — use `secret edit` instead")
	cmd.Flags().String("regeneration-instructions", "", "Rotation notes, applied only when creating; on an existing secret this errors — use `secret edit` instead")
	cmd.Flags().Bool("update-only", false, "Refuse to create the secret if it does not exist")
	cmd.Flags().Bool("create-only", false, "Refuse to rotate the secret if it already exists")
	cmd.Flags().String("grace", "", "On rotation, keep the previous value retrievable via `secret reveal --version previous` for this duration (e.g. 30m, 2h, 24h). Format: <int><h|m|s>, range 1m..168h. Errors if the secret does not yet exist (no rotation happens on creation).")
	return cmd
}

func newSecretUpdateCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update <secret-name>",
		Short: "Rotate an existing secret's value (alias of `set --update-only`)",
		Long: `Rotate the value of an existing secret. Fails if the secret does
not exist — for create-or-rotate semantics use ` + "`secrevo secret set`" + `.

Examples:

  secrevo secret update OPENAI_API_KEY --value "sk-live-..."
  pbpaste | secrevo secret update OPENAI_API_KEY --from-stdin
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretSet(cmd, opts, args[0], true)
		},
	}
	cmd.Flags().String("value", "", "Literal secret value (cannot combine with --from-file/--from-stdin)")
	cmd.Flags().String("from-file", "", "Read the secret value from a file path")
	cmd.Flags().Bool("from-stdin", false, "Read the secret value from stdin until EOF")
	cmd.Flags().String("grace", "", "Keep the previous value retrievable via `secret reveal --version previous` for this duration (e.g. 30m, 2h, 24h). Format: <int><h|m|s>, range 1m..168h.")
	return cmd
}

func runSecretSet(cmd *cobra.Command, opts Options, name string, forceUpdateOnly bool) error {
	workspaceID, err := workspaceID(cmd)
	if err != nil {
		return err
	}

	value, err := readSecretValue(cmd, opts)
	if err != nil {
		return err
	}

	updateOnly := forceUpdateOnly
	if !forceUpdateOnly {
		updateOnly, _ = cmd.Flags().GetBool("update-only")
	}
	createOnly, _ := cmd.Flags().GetBool("create-only")
	if updateOnly && createOnly {
		return fmt.Errorf("--update-only and --create-only are mutually exclusive")
	}
	description, _ := cmd.Flags().GetString("description")
	regeneration, _ := cmd.Flags().GetString("regeneration-instructions")
	grace := ""
	if f := cmd.Flags().Lookup("grace"); f != nil {
		grace = strings.TrimSpace(f.Value.String())
	}
	if grace != "" {
		if !graceDurationRe.MatchString(grace) {
			return fmt.Errorf("--grace must match <int><h|m|s> (e.g. 30m, 2h, 24h); got %q", grace)
		}
	}

	return withClient(opts, func(api APIClient) error {
		list, err := api.ListSecrets(cmd.Context(), workspaceID)
		if err != nil {
			return fmt.Errorf("list secrets: %w", err)
		}

		existing := findSecretByName(list.Secrets, name)
		if existing != nil {
			if createOnly {
				return fmt.Errorf("secret %q already exists in workspace %q", name, workspaceID)
			}
			// --description / --regeneration-instructions only apply when
			// creating. On a rotation they would be silently discarded, so
			// fail loud and point at the metadata-only command instead of
			// pretending the metadata was saved.
			if cmd.Flags().Changed("description") || cmd.Flags().Changed("regeneration-instructions") {
				return fmt.Errorf(
					"--description and --regeneration-instructions apply only when creating a secret; %q already exists. "+
						"To rotate its value, drop those flags; to change its metadata without rotating, use `secrevo secret edit %s`.",
					name, name,
				)
			}
			if err := api.RotateSecretValue(cmd.Context(), workspaceID, existing.SecretID, value, grace); err != nil {
				return fmt.Errorf("rotate secret value: %w", err)
			}
			if grace != "" {
				_, _ = fmt.Fprintf(opts.Out, "Rotated secret %q (%s) in workspace %s (grace: previous value retrievable for %s)\n", name, existing.SecretID, workspaceID, grace)
			} else {
				_, _ = fmt.Fprintf(opts.Out, "Rotated secret %q (%s) in workspace %s\n", name, existing.SecretID, workspaceID)
			}
			return nil
		}

		if grace != "" {
			return fmt.Errorf(
				"--grace applies only to rotation; the secret %q doesn't exist yet. "+
					"Use `secret set %s --value ...` without --grace to create it first, then rotate with --grace.",
				name, name,
			)
		}

		if updateOnly {
			available := secretNames(list.Secrets)
			return fmt.Errorf(
				"secret %q not found in workspace %q. Available: %s",
				name, workspaceID, strings.Join(available, ", "),
			)
		}

		created, err := api.CreateSecret(cmd.Context(), workspaceID, client.SecretCreateRequest{
			Name:                     name,
			Description:              description,
			RegenerationInstructions: regeneration,
			Value:                    value,
		})
		if err != nil {
			return fmt.Errorf("create secret: %w", err)
		}
		_, _ = fmt.Fprintf(opts.Out, "Created secret %q (%s) in workspace %s\n", created.Name, created.SecretID, workspaceID)
		return nil
	})
}

// graceDurationRe matches the `<int><h|m|s>` format accepted by the api.
// Range validation (1m..168h) happens server-side; the client only ensures
// the shape is valid so we can fail before the HTTP round-trip on obvious
// typos. Leading zeros are rejected to keep parity with the api's parser.
var graceDurationRe = mustCompileGraceRe()

func readSecretValue(cmd *cobra.Command, opts Options) (string, error) {
	literal, _ := cmd.Flags().GetString("value")
	path, _ := cmd.Flags().GetString("from-file")
	fromStdin, _ := cmd.Flags().GetBool("from-stdin")

	provided := 0
	if literal != "" {
		provided++
	}
	if path != "" {
		provided++
	}
	if fromStdin {
		provided++
	}
	if provided == 0 {
		return "", fmt.Errorf("provide exactly one of --value, --from-file, or --from-stdin")
	}
	if provided > 1 {
		return "", fmt.Errorf("--value, --from-file, and --from-stdin are mutually exclusive")
	}

	if literal != "" {
		return literal, nil
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		return string(data), nil
	}
	stdin := opts.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

func findSecretByName(secrets []client.Secret, name string) *client.Secret {
	for i := range secrets {
		if secrets[i].Name == name {
			return &secrets[i]
		}
	}
	return nil
}

func secretNames(secrets []client.Secret) []string {
	out := make([]string, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, s.Name)
	}
	return out
}

func newAgentCommand(opts Options) *cobra.Command {
	agent := &cobra.Command{
		Use:   "agent",
		Short: "Agent commands",
	}
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a workspace agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceID, err := workspaceID(cmd)
			if err != nil {
				return err
			}
			description, _ := cmd.Flags().GetString("description")
			return withClient(opts, func(api APIClient) error {
				resp, err := api.CreateAgent(cmd.Context(), workspaceID, client.AgentCreateRequest{
					Name:        args[0],
					Description: strings.TrimSpace(description),
				})
				if err != nil {
					return err
				}
				return writeJSON(opts.Out, resp)
			})
		},
	}
	create.Flags().String("description", "", "Optional agent description")
	agent.AddCommand(create)
	return agent
}

func newRunCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [--secret name[=ENV_VAR]]... -- <command> [args...]",
		Short: "Run a process with Secrevo secrets injected as environment variables",
		Long: `Run a process with Secrevo secrets injected as environment variables.

Each --secret flag names a secret to reveal from the workspace and inject
into the child process. The default env var name is a POSIX-safe form of
the secret name — letters uppercased, anything non-[A-Z0-9_] turned into '_'.
For example a secret named "aws.cloudwatch.webhooks.url" injects as
AWS_CLOUDWATCH_WEBHOOKS_URL. Pass --secret NAME=ENV_NAME to rename
explicitly, or --raw-name to inject under the secret's literal name (only
useful when the operator knows their shell handles the non-POSIX form).

--all injects every secret visible to the current token (one reveal per
secret, sanitized env var name) and cannot be combined with --secret.

The child inherits stdin/stdout/stderr and the calling process's environment
(plus the injected secrets). SIGINT/SIGTERM received by the CLI are
forwarded to the child so wrappers like ` + "`docker run`" + ` and ` + "`kubectl`" + ` get
their normal cleanup window. On exit, the CLI exits with the same status
code as the child.

Two extra variables are injected so the child can detect it is running
under ` + "`secrevo run`" + ` and which workspace it was launched against:
SECREVO_RUN=1, SECREVO_WORKSPACE_ID=<id>.

Examples:

  secrevo run --secret OPENAI_API_KEY -- python app.py
  secrevo run --secret AWS_ACCESS_KEY_ID --secret AWS_SECRET_ACCESS_KEY -- aws s3 ls
  secrevo run --secret prod-stripe=STRIPE_API_KEY -- npm test
  secrevo run --secret aws.cloudwatch.webhooks.url --raw-name -- legacy-script
  secrevo run --all -- python agent.py
`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceID, err := workspaceID(cmd)
			if err != nil {
				return err
			}
			rawSpecs, _ := cmd.Flags().GetStringArray("secret")
			rawName, _ := cmd.Flags().GetBool("raw-name")
			injectAll, _ := cmd.Flags().GetBool("all")
			if injectAll && len(rawSpecs) > 0 {
				return fmt.Errorf("--all cannot be combined with --secret; --all already injects every visible secret")
			}

			api, err := getClient(opts)
			if err != nil {
				return err
			}

			var (
				specs []secretSpec
				env   []string
			)
			if injectAll {
				list, err := api.ListSecrets(cmd.Context(), workspaceID)
				if err != nil {
					return fmt.Errorf("list workspace secrets: %w", err)
				}
				specs, err = allSecretSpecs(list.Secrets, !rawName)
				if err != nil {
					return err
				}
				env, err = buildInjectedEnvFromList(cmd.Context(), api, workspaceID, list, specs)
				if err != nil {
					return err
				}
			} else {
				specs, err = parseSecretSpecs(rawSpecs, !rawName)
				if err != nil {
					return err
				}
				env, err = buildInjectedEnvByName(cmd.Context(), api, workspaceID, specs)
				if err != nil {
					return err
				}
			}

			runner := opts.Runner
			if runner == nil {
				runner = osExecRunner{}
			}
			stdin := opts.Stdin
			if stdin == nil {
				stdin = os.Stdin
			}

			return runner.Run(cmd.Context(), RunSpec{
				Command: args[0],
				Args:    args[1:],
				Env:     env,
				Stdin:   stdin,
				Stdout:  opts.Out,
				Stderr:  opts.Err,
			})
		},
	}
	cmd.Flags().StringArrayP("secret", "s", nil, "Secret to inject (repeatable). Format: NAME or NAME=ENV_VAR_NAME.")
	cmd.Flags().Bool("raw-name", false, "Inject under the secret's literal name (skip POSIX sanitization)")
	cmd.Flags().Bool("all", false, "Inject every secret visible to the current token (mutually exclusive with --secret)")
	return cmd
}

// allSecretSpecs builds one spec per visible secret. When sanitize is true
// the env var name is the POSIX form of the secret name; otherwise the
// literal name is used. Conflicts after sanitization fail loud so the
// operator notices instead of silently overwriting an env var.
func allSecretSpecs(secrets []client.Secret, sanitize bool) ([]secretSpec, error) {
	specs := make([]secretSpec, 0, len(secrets))
	seen := make(map[string]string, len(secrets))
	for _, s := range secrets {
		envName := s.Name
		if sanitize {
			envName = sanitizeEnvName(s.Name)
		}
		if envName == "" {
			return nil, fmt.Errorf("secret %q sanitizes to empty env var name", s.Name)
		}
		if previous, ok := seen[envName]; ok {
			return nil, fmt.Errorf("--all would set env var %q twice (from secrets %q and %q); rename one of them or pass explicit --secret flags", envName, previous, s.Name)
		}
		seen[envName] = s.Name
		specs = append(specs, secretSpec{secretName: s.Name, envName: envName})
	}
	return specs, nil
}

// secretSpec is one --secret flag value: a secret name plus the env var
// name to inject it under (defaulting to the secret name).
type secretSpec struct {
	secretName string
	envName    string
}

// parseSecretSpecs parses repeated --secret flags into specs. When the
// operator wrote NAME (no '='), the env var name defaults to a sanitized
// form of NAME so an imported secret named `aws.cloudwatch.webhooks.url`
// lands as the portable `AWS_CLOUDWATCH_WEBHOOKS_URL`. Pass sanitizeDefault
// false (e.g. when --raw-name is set) to keep the raw secret name as the
// env var — only useful when the operator knows their shell tolerates the
// non-POSIX form.
//
// When the operator wrote NAME=ENV_VAR the explicit env var is preserved
// verbatim regardless of sanitizeDefault: an explicit rename signals the
// operator picked the form they want.
func parseSecretSpecs(raw []string, sanitizeDefault bool) ([]secretSpec, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("at least one --secret flag is required")
	}
	out := make([]secretSpec, 0, len(raw))
	seen := make(map[string]string)
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("--secret cannot be empty")
		}
		secretName := entry
		var envName string
		explicit := false
		if i := strings.Index(entry, "="); i >= 0 {
			secretName = strings.TrimSpace(entry[:i])
			envName = strings.TrimSpace(entry[i+1:])
			explicit = true
		}
		if secretName == "" {
			return nil, fmt.Errorf("--secret %q has empty secret name", entry)
		}
		if !explicit {
			envName = secretName
			if sanitizeDefault {
				envName = sanitizeEnvName(secretName)
			}
		}
		if envName == "" {
			return nil, fmt.Errorf("--secret %q has empty env var name", entry)
		}
		if previous, ok := seen[envName]; ok {
			return nil, fmt.Errorf("env var %q would be set twice (from %q and %q)", envName, previous, secretName)
		}
		seen[envName] = secretName
		out = append(out, secretSpec{secretName: secretName, envName: envName})
	}
	return out, nil
}

// buildInjectedEnvFromList reveals each spec by resolving its secretID from
// the provided list and calling the by-id reveal endpoint. Used by --all,
// which has already paid for a ListSecrets call to enumerate every visible
// secret.
//
// Reveal calls happen sequentially because each one emits a separate audit
// event and the caller wants deterministic ordering in the audit log.
//
// Two context variables are always appended so the child can detect it
// runs under `secrevo run` and which workspace was used: SECREVO_RUN=1 and
// SECREVO_WORKSPACE_ID=<id>. They never carry the agent token — if the
// child needs to call the API it must inherit SECREVO_API_TOKEN from the
// parent environment explicitly.
func buildInjectedEnvFromList(ctx context.Context, api APIClient, workspaceID string, list client.SecretListResponse, specs []secretSpec) ([]string, error) {
	available := make([]string, 0, len(list.Secrets))
	for _, s := range list.Secrets {
		available = append(available, s.Name)
	}

	env := contextEnv(workspaceID)
	for _, spec := range specs {
		secretID, err := resolveSecretID(list.Secrets, spec.secretName)
		if err != nil {
			return nil, fmt.Errorf(
				"secret %q not found in workspace %q. Available: %s",
				spec.secretName, workspaceID, strings.Join(available, ", "),
			)
		}
		revealed, err := api.RevealSecretValue(ctx, workspaceID, secretID)
		if err != nil {
			if isForbidden(err) {
				return nil, forbiddenRunError(spec.secretName, err)
			}
			return nil, fmt.Errorf("reveal secret %q: %w", spec.secretName, err)
		}
		env = append(env, spec.envName+"="+revealed.Value)
	}
	return env, nil
}

// buildInjectedEnvByName reveals each spec via the by-name reveal endpoint,
// avoiding ListSecrets (which requires secret.read@workspace). Lets a caller
// with only per-secret grants run `secrevo run --secret X` successfully.
func buildInjectedEnvByName(ctx context.Context, api APIClient, workspaceID string, specs []secretSpec) ([]string, error) {
	env := contextEnv(workspaceID)
	for _, spec := range specs {
		revealed, err := api.RevealSecretValueByName(ctx, workspaceID, spec.secretName, "")
		if err != nil {
			if isForbidden(err) {
				return nil, forbiddenRunError(spec.secretName, err)
			}
			return nil, fmt.Errorf("reveal secret %q: %w", spec.secretName, err)
		}
		env = append(env, spec.envName+"="+revealed.Value)
	}
	return env, nil
}

// forbiddenRunError explains a 403 during `secrevo run`. A run authenticated
// with a HUMAN token needs secret.reveal (it would otherwise be a back-door to
// display the value); the intended runtime path is an AGENT token, which uses
// secret.read. Surfacing this distinction turns an opaque 403 into a fix.
func forbiddenRunError(secretName string, err error) error {
	return fmt.Errorf(
		"reveal secret %q: not authorized to inject this value.\n"+
			"  Runtime injection with an agent token requires \"secret.read\" on the secret;\n"+
			"  a human token additionally requires \"secret.reveal\". If this is meant to run\n"+
			"  unattended, use an agent token in SECREVO_API_TOKEN. Otherwise ask a workspace\n"+
			"  admin to grant the missing capability. (%w)",
		secretName, err,
	)
}

func contextEnv(workspaceID string) []string {
	env := os.Environ()
	env = append(env, "SECREVO_RUN=1")
	env = append(env, "SECREVO_WORKSPACE_ID="+workspaceID)
	return env
}

// Runner abstracts subprocess execution so tests can record calls without
// actually exec-ing anything.
type Runner interface {
	Run(ctx context.Context, spec RunSpec) error
}

// RunSpec is the data the Runner needs to spawn the child. Stdout and
// Stderr are deliberately the same writers the cobra command was given so
// tests can read what the child "wrote".
type RunSpec struct {
	Command string
	Args    []string
	Env     []string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

type osExecRunner struct{}

// Run starts the child process and forwards SIGINT/SIGTERM/SIGHUP from
// the CLI process to the child so wrappers like `docker run`, `kubectl
// port-forward`, or `terraform apply` get their normal cleanup window
// when the operator hits Ctrl-C. Using exec.CommandContext's default
// Cancel would SIGKILL the child instead, which strands containers and
// half-applied state.
func (osExecRunner) Run(ctx context.Context, spec RunSpec) error {
	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Env = spec.Env
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

	err := cmd.Wait()
	close(done)

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return cliExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("run %s: %w", spec.Command, err)
	}
	return nil
}

// forwardSignals relays OS signals received by the CLI to the child
// process and exits when the child has been waited on (done closed) or
// the caller cancels the context. Errors from Process.Signal are
// intentionally swallowed: by the time a signal arrives the child may
// already have exited and the next select iteration handles it.
func forwardSignals(proc *os.Process, ctx context.Context, sigCh <-chan os.Signal, done <-chan struct{}) {
	for {
		select {
		case sig := <-sigCh:
			_ = proc.Signal(sig)
		case <-ctx.Done():
			_ = proc.Signal(os.Interrupt)
		case <-done:
			return
		}
	}
}

// cliExitError is recognized by the cobra Execute caller to translate the
// child's exit code into the CLI's own exit code without printing the
// underlying error twice.
type cliExitError struct {
	Code int
}

func (e cliExitError) Error() string {
	return fmt.Sprintf("subprocess exited with code %d", e.Code)
}

// ExitCode reports the exit code carried by an error returned from
// Execute, defaulting to 1 for non-cliExitError failures and 0 on
// success. The main package converts this to os.Exit so the CLI
// process's exit code matches what the user expects when running
// `secrevo run -- <command>`.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr cliExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return 1
}

func withClient(opts Options, fn func(APIClient) error) error {
	api, err := getClient(opts)
	if err != nil {
		return err
	}
	return fn(api)
}

func getClient(opts Options) (APIClient, error) {
	api, err := opts.ClientFactory()
	if err != nil {
		if errors.Is(err, client.ErrNotConfigured) {
			return nil, fmt.Errorf("secrevo API client is not configured: set SECREVO_API_BASE_URL and SECREVO_API_TOKEN")
		}
		return nil, err
	}
	return api, nil
}

func workspaceID(cmd *cobra.Command) (string, error) {
	value, err := cmd.Flags().GetString("workspace-id")
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("workspace id is required: set --workspace-id or SECREVO_WORKSPACE_ID")
	}
	return value, nil
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func resolveSecretID(secrets []client.Secret, query string) (string, error) {
	for _, secret := range secrets {
		if secret.SecretID == query || secret.Name == query {
			return secret.SecretID, nil
		}
	}
	return "", fmt.Errorf("secret not found: %s", query)
}
