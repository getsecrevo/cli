package app

import (
	"github.com/spf13/cobra"
)

// newSecretAgentReadCommand manages a secret's per-secret agent raw-read opt-in
// (human-only server-side). By default an agent cannot read a secret's raw value;
// the owner uses `allow` for a secret they deem low-risk (public config, or a key
// already protected by MFA + scoped permissions) so their agent can read it. Use
// `deny` to revert to the safe default.
func newSecretAgentReadCommand(opts Options) *cobra.Command {
	ar := &cobra.Command{
		Use:   "agent-read",
		Short: "Allow/deny an agent to read a secret's raw value (human only)",
		Long: "By default an agent cannot read a secret's raw value. `allow` opts a specific\n" +
			"secret in — for a value you deem low-risk, or already protected by other means\n" +
			"(MFA, scoped permissions) — so your agent can read it; Secrevo then only reduces\n" +
			"exposure. `deny` reverts to the safe default.",
	}

	allow := &cobra.Command{
		Use:   "allow --secret NAME",
		Short: "Allow agents (with secret.read) to read this secret's raw value",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSetAgentRead(cmd, opts, true)
		},
	}
	allow.Flags().String("secret", "", "secret name (required)")
	_ = allow.MarkFlagRequired("secret")

	deny := &cobra.Command{
		Use:   "deny --secret NAME",
		Short: "Revert to the default: agents cannot read this secret's raw value",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSetAgentRead(cmd, opts, false)
		},
	}
	deny.Flags().String("secret", "", "secret name (required)")
	_ = deny.MarkFlagRequired("secret")

	ar.AddCommand(allow, deny)
	return ar
}

func runSetAgentRead(cmd *cobra.Command, opts Options, allowed bool) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	return withClient(opts, func(api APIClient) error {
		secretID, err := resolveSecretName(cmd, api, ws, name)
		if err != nil {
			return err
		}
		if err := api.SetAgentRead(cmd.Context(), ws, secretID, allowed); err != nil {
			return err
		}
		state := "denied"
		if allowed {
			state = "allowed"
		}
		return writeJSON(opts.Out, map[string]any{"secret": name, "agent_raw_read": state})
	})
}
