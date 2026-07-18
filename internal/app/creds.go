package app

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/getsecrevo/cli/internal/client"
	"github.com/spf13/cobra"
)

// newCredsCommand implements `secrevo creds` — mint a short-lived, scoped
// ephemeral credential for a secret (F3, INV-11). Unlike `secrevo call`
// (mediated, value never seen), the cred DOES come back to this process: it is
// the honest answer for loads that must see bytes (AWS SigV4 signing, DB
// clients). The cred is TTL-bounded + scoped; the CLI prints it and NEVER
// persists it. The signature use of --format aws-process is the clean AWS unlock:
// configure `credential_process = secrevo creds --secret X --format aws-process`
// and the AWS CLI fetches fresh scoped creds itself — no long-lived key in hand.
func newCredsCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "creds --secret NAME [--ttl 15m] [--format env|json|aws-process]",
		Short: "Mint a short-lived, scoped credential for a secret (for non-HTTP loads)",
		Long: "For loads where some process MUST see credential bytes (AWS SigV4, DB clients),\n" +
			"mint a short-lived scoped credential instead of handling the long-lived key.\n" +
			"The credential is never persisted by the CLI. The secret must have a cred-scope\n" +
			"set by a human (`secrevo secret cred-scope add`); otherwise the mint is refused.\n\n" +
			"Formats:\n" +
			"  json          raw JSON (default)\n" +
			"  env           export AWS_ACCESS_KEY_ID=... lines (for `eval $(secrevo creds ...)`)\n" +
			"  aws-process   AWS CLI credential_process format (put it in ~/.aws/config)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCreds(cmd, opts)
		},
	}
	cmd.Flags().StringP("secret", "s", "", "secret name to mint an ephemeral credential for (required)")
	cmd.Flags().String("ttl", "", "requested credential lifetime, e.g. 15m (server clamps to the scope + role caps)")
	cmd.Flags().String("format", "json", "output format: json | env | aws-process")
	_ = cmd.MarkFlagRequired("secret")
	return cmd
}

func runCreds(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	format, _ := cmd.Flags().GetString("format")
	ttlRaw, _ := cmd.Flags().GetString("ttl")

	ttlSeconds := 0
	if ttlRaw != "" {
		d, err := time.ParseDuration(ttlRaw)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid --ttl %q: use a positive duration like 15m or 1h", ttlRaw)
		}
		ttlSeconds = int(d.Seconds())
	}
	switch format {
	case "json", "env", "aws-process":
	default:
		return fmt.Errorf("invalid --format %q: use json | env | aws-process", format)
	}

	return withClient(opts, func(api APIClient) error {
		cred, err := api.MintCreds(cmd.Context(), ws, name, ttlSeconds)
		if err != nil {
			return err
		}
		return printCred(opts, cred, format)
	})
}

// printCred renders a minted credential in the requested format. Only aws_sts
// creds have an env/aws-process shape today; a future db provider prints json.
func printCred(opts Options, cred client.Cred, format string) error {
	switch format {
	case "env":
		if cred.Provider != client.CredProviderAWSSTS {
			return fmt.Errorf("--format env is only supported for aws_sts credentials (got %q); use --format json", cred.Provider)
		}
		fmt.Fprintf(opts.Out, "export AWS_ACCESS_KEY_ID=%s\n", cred.AccessKeyID)
		fmt.Fprintf(opts.Out, "export AWS_SECRET_ACCESS_KEY=%s\n", cred.SecretAccessKey)
		fmt.Fprintf(opts.Out, "export AWS_SESSION_TOKEN=%s\n", cred.SessionToken)
		return nil
	case "aws-process":
		if cred.Provider != client.CredProviderAWSSTS {
			return fmt.Errorf("--format aws-process is only supported for aws_sts credentials (got %q)", cred.Provider)
		}
		// The exact shape the AWS CLI/SDK expects from a credential_process.
		out := map[string]any{
			"Version":         1,
			"AccessKeyId":     cred.AccessKeyID,
			"SecretAccessKey": cred.SecretAccessKey,
			"SessionToken":    cred.SessionToken,
			"Expiration":      cred.Expiration,
		}
		enc := json.NewEncoder(opts.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	default: // json
		return writeJSON(opts.Out, cred)
	}
}

// newSecretCredScopeCommand manages a secret's ephemeral-credential scope
// (human-only server-side: an agent can never widen its own credential scope).
// The scope declares what kind of cred `secrevo creds` mints and its bounds. The
// role_arn is re-clamped by the mediator against an IaC allowlist at mint time,
// so declaring one here does not by itself grant access to it.
func newSecretCredScopeCommand(opts Options) *cobra.Command {
	cs := &cobra.Command{
		Use:   "cred-scope",
		Short: "Manage the ephemeral-credential scope for a secret (human only)",
	}

	add := &cobra.Command{
		Use:   "add --secret NAME --provider aws_sts --role-arn ARN [flags]",
		Short: "Declare what ephemeral credential a secret mints and its bounds",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCredScopeAdd(cmd, opts)
		},
	}
	add.Flags().String("secret", "", "secret name (required)")
	add.Flags().String("provider", "aws_sts", "cred provider: aws_sts | db")
	add.Flags().String("role-arn", "", "aws_sts: IAM role ARN to assume (must be on the mediator's IaC allowlist)")
	add.Flags().String("session-policy", "", "aws_sts: optional inline session policy JSON (can only REDUCE scope)")
	add.Flags().String("db-role", "", "db: OpenBao database engine role name")
	add.Flags().String("max-ttl", "", "cap the credential lifetime for this secret, e.g. 15m")
	_ = add.MarkFlagRequired("secret")

	list := &cobra.Command{
		Use:   "list --secret NAME",
		Short: "Show a secret's ephemeral-credential scope",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCredScopeList(cmd, opts)
		},
	}
	list.Flags().String("secret", "", "secret name (required)")
	_ = list.MarkFlagRequired("secret")

	rm := &cobra.Command{
		Use:   "rm --secret NAME",
		Short: "Remove a secret's ephemeral-credential scope",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCredScopeRemove(cmd, opts)
		},
	}
	rm.Flags().String("secret", "", "secret name (required)")
	_ = rm.MarkFlagRequired("secret")

	cs.AddCommand(add, list, rm)
	return cs
}

func runCredScopeAdd(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	provider, _ := cmd.Flags().GetString("provider")
	roleARN, _ := cmd.Flags().GetString("role-arn")
	sessionPolicy, _ := cmd.Flags().GetString("session-policy")
	dbRole, _ := cmd.Flags().GetString("db-role")
	maxTTLRaw, _ := cmd.Flags().GetString("max-ttl")

	config := map[string]string{}
	switch provider {
	case client.CredProviderAWSSTS:
		if roleARN == "" {
			return fmt.Errorf("--role-arn is required for provider aws_sts")
		}
		config["role_arn"] = roleARN
		if sessionPolicy != "" {
			config["session_policy"] = sessionPolicy
		}
	case client.CredProviderDB:
		if dbRole == "" {
			return fmt.Errorf("--db-role is required for provider db")
		}
		config["openbao_db_role"] = dbRole
	default:
		return fmt.Errorf("unknown --provider %q (aws_sts | db)", provider)
	}

	maxTTLSeconds := 0
	if maxTTLRaw != "" {
		d, err := time.ParseDuration(maxTTLRaw)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid --max-ttl %q: use a positive duration like 15m", maxTTLRaw)
		}
		maxTTLSeconds = int(d.Seconds())
	}

	return withClient(opts, func(api APIClient) error {
		secretID, err := resolveSecretName(cmd, api, ws, name)
		if err != nil {
			return err
		}
		saved, err := api.PutCredScope(cmd.Context(), ws, secretID, client.CredScope{
			Provider: provider, Config: config, MaxTTLSeconds: maxTTLSeconds,
		})
		if err != nil {
			return err
		}
		return writeJSON(opts.Out, saved)
	})
}

func runCredScopeList(cmd *cobra.Command, opts Options) error {
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
		scope, err := api.GetCredScope(cmd.Context(), ws, secretID)
		if err != nil {
			return err
		}
		return writeJSON(opts.Out, scope)
	})
}

func runCredScopeRemove(cmd *cobra.Command, opts Options) error {
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
		return api.DeleteCredScope(cmd.Context(), ws, secretID)
	})
}
