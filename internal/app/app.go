package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	CreateAgent(context.Context, string, client.AgentCreateRequest) (client.AgentCreateResponse, error)
}

type Options struct {
	Version       string
	WorkspaceID   string
	ClientFactory func() (APIClient, error)
	Out           io.Writer
	Err           io.Writer
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
	return &cobra.Command{
		Use:   "run -- <command>",
		Short: "Print the command invocation contract",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := getClient(opts)
			if err != nil {
				return err
			}
			workspaceID, err := workspaceID(cmd)
			if err != nil {
				return err
			}
			contract := map[string]any{
				"workspace_id": workspaceID,
				"command":      args,
				"api_base_url": api.BaseURL(),
				"status":       "contract-only",
				"note":         "execution is not wired yet",
			}
			return writeJSON(opts.Out, contract)
		},
	}
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
