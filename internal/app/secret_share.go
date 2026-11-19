package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/getsecrevo/cli/internal/client"
)

// secretSharer is the slice of the api client the `secret share` commands
// need, discovered by type assertion like secretRequester.
type secretSharer interface {
	CreateSecretShareByName(context.Context, string, string, client.SecretShareCreateRequest) (client.SecretShareCreated, error)
	ListSecretShares(context.Context, string, string) ([]client.SecretShare, error)
	CancelSecretShare(context.Context, string, string) (client.SecretShareCancelled, error)
}

var _ secretSharer = (*client.Client)(nil)

func asSecretSharer(api APIClient) (secretSharer, error) {
	ss, ok := api.(secretSharer)
	if !ok {
		return nil, fmt.Errorf("this client does not support external shares")
	}
	return ss, nil
}

// newSecretShareCommand hands a COPY of a secret to someone OUTSIDE the
// workspace through a single-use link.
func newSecretShareCommand(opts Options) *cobra.Command {
	share := &cobra.Command{
		Use:   "share",
		Short: "Share a copy of a secret with someone outside the workspace (single-use link)",
		Long: "Send a customer, vendor or contractor a single-use link that shows them a copy\n" +
			"of one secret's value once. They need no account. The value is encrypted with a\n" +
			"key that only the link carries; Secrevo stores only the ciphertext and destroys it\n" +
			"when the link is opened, cancelled or expires.\n\n" +
			"With an AGENT token this never sends anything: it prepares a request that the\n" +
			"person the agent acts for approves in the Secrevo dashboard with their own MFA\n" +
			"(status pending_approval). The agent never sees the value, the link or a code.\n\n" +
			"With your own login it shares at once, after the same MFA step-up as revealing the\n" +
			"value (sign in again if it answers stepup_required).\n\n" +
			"Safety rails enforced by the server:\n" +
			"  - --secret must be the EXACT name (no fuzzy match).\n" +
			"  - The recipient gets an email code when opening it, unless you pass --no-email-code.\n" +
			"  - --link (you deliver the link yourself) needs a code: keep the email code or add --extra-code.",
	}

	send := &cobra.Command{
		Use:   "send --secret NAME --to EMAIL",
		Short: "Share (or, as an agent, prepare to share) a copy of a secret",
		Example: "  secrevo secret share send --secret \"DB prod\" --to pepito@acme.com\n" +
			"  secrevo secret share send --secret SUNAT_SOL --to contador@acme.com --field usuario --field clave --extra-code",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSecretShareSend(cmd, opts)
		},
	}
	send.Flags().String("secret", "", "the secret's EXACT name (required)")
	send.Flags().String("to", "", "recipient email (required)")
	send.Flags().StringArray("field", nil, "share only this field of a multi-field secret; repeatable (default: all)")
	send.Flags().String("message", "", "short plain-text note for the recipient (no links; ignored for agents)")
	send.Flags().Int("expires-in-hours", 0, "link lifetime in hours, 1-168 (default 72)")
	send.Flags().Bool("no-email-code", false, "do not email the recipient a one-time code when they open it")
	send.Flags().Bool("extra-code", false, "also require a code you pass by phone or chat (printed once)")
	send.Flags().Bool("link", false, "do not email the link; print it so you deliver it yourself")
	_ = send.MarkFlagRequired("secret")
	_ = send.MarkFlagRequired("to")

	list := &cobra.Command{
		Use:   "list [--secret NAME]",
		Short: "List external shares and their status (never values, links or codes)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSecretShareList(cmd, opts)
		},
	}
	list.Flags().String("secret", "", "only the shares of this secret")

	cancel := &cobra.Command{
		Use:   "cancel <share-id>",
		Short: "Cancel an open share so its link stops working",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretShareCancel(cmd, opts, args[0])
		},
	}

	share.AddCommand(send, list, cancel)
	return share
}

func runSecretShareSend(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	to, _ := cmd.Flags().GetString("to")
	fields, _ := cmd.Flags().GetStringArray("field")
	message, _ := cmd.Flags().GetString("message")
	hours, _ := cmd.Flags().GetInt("expires-in-hours")
	noCode, _ := cmd.Flags().GetBool("no-email-code")
	extra, _ := cmd.Flags().GetBool("extra-code")
	link, _ := cmd.Flags().GetBool("link")

	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("--to is required: a share always goes to one named person")
	}
	if link && noCode && !extra {
		return fmt.Errorf("--link needs a code: drop --no-email-code or add --extra-code")
	}
	requireCode := !noCode
	delivery := "email"
	if link {
		delivery = "link"
	}
	return withClient(opts, func(api APIClient) error {
		ss, err := asSecretSharer(api)
		if err != nil {
			return err
		}
		created, err := ss.CreateSecretShareByName(cmd.Context(), ws, name, client.SecretShareCreateRequest{
			RecipientEmail:   to,
			Message:          message,
			Fields:           fields,
			ExpiresInHours:   hours,
			RequireEmailCode: &requireCode,
			ExtraCode:        extra,
			Delivery:         delivery,
		})
		if err != nil {
			return err
		}
		out := map[string]any{
			"share_id":        created.Share.ID,
			"status":          created.Share.Status,
			"secret":          created.Share.SecretName,
			"fields":          created.Share.FieldNames,
			"recipient_email": created.Share.RecipientEmail,
			"email_sent":      created.EmailSent,
			"expires_at":      created.Share.ExpiresAt,
		}
		if created.NextStep != "" {
			out["next_step"] = created.NextStep
		}
		// The link opens the value and the extra code is its second factor:
		// printed only when the api returned them to a person who asked.
		if created.URL != "" {
			out["link"] = created.URL
			out["link_note"] = "deliver this link only to " + created.Share.RecipientEmail + "; it is shown once"
		}
		if created.ExtraCode != "" {
			if created.URL != "" {
				// The link and its second factor never land in the same stream
				// (a captured stdout, a CI log): the code goes to stderr.
				fmt.Fprintf(opts.Err, "extra code (tell %s by phone or chat, not by email; shown once): %s\n", created.Share.RecipientEmail, created.ExtraCode)
			} else {
				out["extra_code"] = created.ExtraCode
				out["extra_code_note"] = "tell " + created.Share.RecipientEmail + " this code by phone or chat, not by email; it is shown once"
			}
		}
		return writeJSON(opts.Out, out)
	})
}

func runSecretShareList(cmd *cobra.Command, opts Options) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	name, _ := cmd.Flags().GetString("secret")
	return withClient(opts, func(api APIClient) error {
		ss, err := asSecretSharer(api)
		if err != nil {
			return err
		}
		secretID := ""
		if name != "" {
			if secretID, err = resolveSecretName(cmd, api, ws, name); err != nil {
				return err
			}
		}
		shares, err := ss.ListSecretShares(cmd.Context(), ws, secretID)
		if err != nil {
			return err
		}
		return writeJSON(opts.Out, map[string]any{"shares": shares})
	})
}

func runSecretShareCancel(cmd *cobra.Command, opts Options, shareID string) error {
	ws, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	return withClient(opts, func(api APIClient) error {
		ss, err := asSecretSharer(api)
		if err != nil {
			return err
		}
		r, err := ss.CancelSecretShare(cmd.Context(), ws, shareID)
		if err != nil {
			return err
		}
		return writeJSON(opts.Out, r)
	})
}
