package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/getsecrevo/cli/internal/client"
	"github.com/spf13/cobra"
)

const defaultVersion = "0.1.0-dev"

type APIClient interface {
	BaseURL() string
	Whoami(context.Context) (client.Session, error)
	BootstrapWorkspace(context.Context, client.BootstrapWorkspaceRequest) (client.BootstrapWorkspaceResponse, error)
	ListSecrets(context.Context, string) (client.SecretListResponse, error)
	GetSecret(context.Context, string, string) (client.Secret, error)
	RevealSecretValue(context.Context, string, string) (client.SecretValue, error)
	CreateAgent(context.Context, string, client.AgentCreateRequest) (client.AgentCreateResponse, error)
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
}

func Execute(args []string, out, errOut io.Writer) error {
	opts := Options{
		Version:     defaultVersion,
		WorkspaceID: strings.TrimSpace(os.Getenv("SECREVO_WORKSPACE_ID")),
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
	return secret
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
into the child process. The default env var name is the secret name verbatim;
pass --secret NAME=ENV_NAME to rename. Multiple --secret flags are allowed,
and values are revealed in parallel before the child process starts.

The child inherits stdin/stdout/stderr and the calling process's environment
(plus the injected secrets). On exit, the CLI exits with the same status
code as the child.

Examples:

  secrevo run --secret OPENAI_API_KEY -- python app.py
  secrevo run --secret AWS_ACCESS_KEY_ID --secret AWS_SECRET_ACCESS_KEY -- aws s3 ls
  secrevo run --secret prod-stripe=STRIPE_API_KEY -- npm test
`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			workspaceID, err := workspaceID(cmd)
			if err != nil {
				return err
			}
			rawSpecs, _ := cmd.Flags().GetStringArray("secret")
			specs, err := parseSecretSpecs(rawSpecs)
			if err != nil {
				return err
			}

			api, err := getClient(opts)
			if err != nil {
				return err
			}

			env, err := buildInjectedEnv(cmd.Context(), api, workspaceID, specs)
			if err != nil {
				return err
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
	return cmd
}

// secretSpec is one --secret flag value: a secret name plus the env var
// name to inject it under (defaulting to the secret name).
type secretSpec struct {
	secretName string
	envName    string
}

func parseSecretSpecs(raw []string) ([]secretSpec, error) {
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
		secretName, envName := entry, entry
		if i := strings.Index(entry, "="); i >= 0 {
			secretName = strings.TrimSpace(entry[:i])
			envName = strings.TrimSpace(entry[i+1:])
		}
		if secretName == "" {
			return nil, fmt.Errorf("--secret %q has empty secret name", entry)
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

// buildInjectedEnv reveals each secret and returns the parent environment
// extended with the injected variables. Reveal calls happen sequentially
// because each one emits a separate audit event and the caller wants
// deterministic ordering in the audit log.
func buildInjectedEnv(ctx context.Context, api APIClient, workspaceID string, specs []secretSpec) ([]string, error) {
	list, err := api.ListSecrets(ctx, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("list workspace secrets: %w", err)
	}
	available := make([]string, 0, len(list.Secrets))
	for _, s := range list.Secrets {
		available = append(available, s.Name)
	}

	env := os.Environ()
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
			return nil, fmt.Errorf("reveal secret %q: %w", spec.secretName, err)
		}
		env = append(env, spec.envName+"="+revealed.Value)
	}
	return env, nil
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

func (osExecRunner) Run(ctx context.Context, spec RunSpec) error {
	cmd := exec.CommandContext(ctx, spec.Command, spec.Args...)
	cmd.Env = spec.Env
	cmd.Stdin = spec.Stdin
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr
	if err := cmd.Run(); err != nil {
		// Surface the child's exit code as the CLI's exit code.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return cliExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("run %s: %w", spec.Command, err)
	}
	return nil
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
