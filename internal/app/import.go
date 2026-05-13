package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/getsecrevo/cli/internal/client"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newImportCommand(opts Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <yaml-file>",
		Short: "Bulk-import secrets from a devvault-style YAML file",
		Long: `Walk a YAML file and create one Secrevo secret per leaf value.

Each scalar leaf becomes a secret named by its path joined with --separator
(default '_'), optionally prefixed with --prefix. For example, with this
file:

  cloudflare:
    secrevo:
      token: cf-token-xyz
      account_id: 007761758105

and ` + "`--prefix cf`" + `, the command creates two secrets:

  cf_cloudflare_secrevo_token
  cf_cloudflare_secrevo_account_id

The '_' default keeps secret names compatible with POSIX environment
variable names so ` + "`secrevo env`" + ` and ` + "`secrevo run`" + ` inject them under the
same name without sanitization. Pass --separator '.' for the legacy
devvault-style dotted names (you'll need --raw-name on env/run for them
to be usable in shells).

Sequences of scalars (e.g. ` + "`redirect_uris: [a, b, c]`" + `) are serialized as
JSON arrays and imported as a single secret whose description records
the conversion. Mixed/nested sequences and aliases are skipped and
reported in the summary. Numbers and booleans are coerced to their YAML
string form (the secret value type is text). Duplicates within the file
abort the run before any API call.

By default the command rotates already-existing secrets; pass --skip-existing
to leave them alone. --dry-run prints the plan without touching the API.

If <file> begins with the Recovery Kit magic header (` + "`SECREVOKIT01`" + `),
the command treats it as a kit instead of YAML: decrypts it with the
passphrase you supply, then routes the embedded secrets through the
same create-or-rotate code path. --separator / --prefix do NOT apply
to kit imports — secret names round-trip unchanged so a kit produced
by ` + "`secrevo export --kit`" + ` is faithfully restored.

Examples:

  secrevo import ~/.devvault/secrevo/cloudwatch.yml
  secrevo import ~/.devvault/cloudflare.yml --prefix cloudflare
  secrevo import ~/.devvault/aws.yml --dry-run

  # Restore from a recovery kit (companion to ` + "`secrevo export --kit`" + `):
  secrevo import ~/secrevo-recovery/secrevo-backup-2026-05-13.json.kit \
      --passphrase-file ~/secrevo-recovery/secrevo-backup-2026-05-13.passphrase
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImport(cmd, opts, args[0])
		},
	}
	cmd.Flags().String("prefix", "", "Prefix prepended to every secret name (joined by the separator) — YAML-mode only")
	cmd.Flags().Bool("dry-run", false, "Print the plan without creating or rotating any secret")
	cmd.Flags().Bool("skip-existing", false, "Skip secrets that already exist instead of rotating their value")
	cmd.Flags().String("separator", "_", "Separator between path components when generating secret names — YAML-mode only")
	cmd.Flags().String("passphrase", "", "Recovery Kit passphrase (text). Mutually exclusive with --passphrase-file / --passphrase-from-stdin.")
	cmd.Flags().String("passphrase-file", "", "Path to a file containing the Recovery Kit passphrase (trailing whitespace trimmed)")
	cmd.Flags().Bool("passphrase-from-stdin", false, "Read the Recovery Kit passphrase from stdin until EOF")
	return cmd
}

func runImport(cmd *cobra.Command, opts Options, path string) error {
	workspaceID, err := workspaceID(cmd)
	if err != nil {
		return err
	}
	prefix, _ := cmd.Flags().GetString("prefix")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipExisting, _ := cmd.Flags().GetBool("skip-existing")
	separator, _ := cmd.Flags().GetString("separator")
	if separator == "" {
		return fmt.Errorf("--separator cannot be empty")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	// Recovery Kit detection: a kit file always starts with the
	// SECREVOKIT01 magic header (see recovery_kit.go). Branch into the
	// kit-import path before attempting to parse the file as YAML — a
	// kit's first bytes are not valid YAML so yaml.Unmarshal would error
	// with a confusing message.
	var leaves []importLeaf
	var skipped []string
	if isRecoveryKit(raw) {
		if prefix != "" {
			return fmt.Errorf("--prefix is not supported in recovery-kit mode (names round-trip unchanged)")
		}
		leaves, err = importLeavesFromRecoveryKit(cmd, opts, raw)
		if err != nil {
			return err
		}
	} else {
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		leaves, skipped, err = flattenYAML(&doc, prefix, separator)
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
	}
	if len(leaves) == 0 {
		return fmt.Errorf("no importable secrets found in %s", path)
	}

	// Detect intra-file duplicates before talking to the API.
	seen := make(map[string]struct{}, len(leaves))
	for _, leaf := range leaves {
		if _, dup := seen[leaf.name]; dup {
			return fmt.Errorf("duplicate secret name in import: %q", leaf.name)
		}
		seen[leaf.name] = struct{}{}
	}

	if dryRun {
		return printImportPlan(opts, leaves, skipped, separator)
	}

	return withClient(opts, func(api APIClient) error {
		list, err := api.ListSecrets(cmd.Context(), workspaceID)
		if err != nil {
			return fmt.Errorf("list secrets: %w", err)
		}
		byName := make(map[string]client.Secret, len(list.Secrets))
		for _, s := range list.Secrets {
			byName[s.Name] = s
		}

		var created, rotated, skippedExisting int
		for _, leaf := range leaves {
			if existing, ok := byName[leaf.name]; ok {
				if skipExisting {
					skippedExisting++
					continue
				}
				if err := api.RotateSecretValue(cmd.Context(), workspaceID, existing.SecretID, leaf.value); err != nil {
					return fmt.Errorf("rotate %s: %w", leaf.name, err)
				}
				rotated++
				continue
			}
			if _, err := api.CreateSecret(cmd.Context(), workspaceID, client.SecretCreateRequest{
				Name:        leaf.name,
				Value:       leaf.value,
				Description: leaf.description,
			}); err != nil {
				return fmt.Errorf("create %s: %w", leaf.name, err)
			}
			created++
		}

		_, _ = fmt.Fprintf(opts.Out,
			"Imported %d leaves from %s: %d created, %d rotated, %d skipped-existing, %d non-scalar leaves skipped.\n",
			len(leaves), path, created, rotated, skippedExisting, len(skipped))
		if len(skipped) > 0 {
			_, _ = fmt.Fprintf(opts.Err, "Non-scalar leaves skipped:\n")
			for _, name := range skipped {
				_, _ = fmt.Fprintf(opts.Err, "  - %s\n", name)
			}
		}
		return nil
	})
}

func printImportPlan(opts Options, leaves []importLeaf, skipped []string, separator string) error {
	sorted := append([]importLeaf(nil), leaves...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	_, _ = fmt.Fprintf(opts.Out, "Dry-run: %d secret(s) would be created or rotated (separator=%q):\n", len(sorted), separator)
	for _, leaf := range sorted {
		_, _ = fmt.Fprintf(opts.Out, "  %s\n", leaf.name)
	}
	if len(skipped) > 0 {
		_, _ = fmt.Fprintf(opts.Out, "\nNon-scalar leaves skipped (%d):\n", len(skipped))
		for _, name := range skipped {
			_, _ = fmt.Fprintf(opts.Out, "  %s\n", name)
		}
	}
	return nil
}

// importLeaf is one scalar leaf discovered while walking the YAML tree.
type importLeaf struct {
	name        string // dotted path, already prefixed
	value       string // scalar text content (numbers/bools coerced to string)
	description string // optional metadata (populated for serialized lists)
}

// flattenYAML walks a yaml.Node tree and returns one importLeaf per scalar
// leaf. Sequences and other non-mapping/non-scalar nodes are recorded in
// “skipped“ (named by their path) so callers can warn the operator.
func flattenYAML(root *yaml.Node, prefix, separator string) ([]importLeaf, []string, error) {
	var leaves []importLeaf
	var skipped []string
	node := root
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return nil, nil, nil
		}
		node = node.Content[0]
	}
	if err := walkYAML(node, prefix, separator, &leaves, &skipped); err != nil {
		return nil, nil, err
	}
	return leaves, skipped, nil
}

func walkYAML(node *yaml.Node, path, separator string, leaves *[]importLeaf, skipped *[]string) error {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			if keyNode.Kind != yaml.ScalarNode {
				continue
			}
			child := joinPath(path, keyNode.Value, separator)
			if err := walkYAML(valueNode, child, separator, leaves, skipped); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if path == "" {
			return fmt.Errorf("top-level scalar without a key")
		}
		*leaves = append(*leaves, importLeaf{name: path, value: node.Value})
	case yaml.SequenceNode:
		if path == "" {
			return nil
		}
		// Sequences of scalars (the common devvault pattern —
		// `redirect_uris: [a, b, c]`) serialize as a JSON array so
		// the secret value round-trips through any consumer that
		// understands JSON. Mixed/nested sequences fall back to the
		// existing "skipped" report.
		values, ok := scalarSequence(node)
		if !ok {
			*skipped = append(*skipped, path)
			return nil
		}
		encoded, err := json.Marshal(values)
		if err != nil {
			return fmt.Errorf("encode YAML list %q as JSON: %w", path, err)
		}
		*leaves = append(*leaves, importLeaf{
			name:        path,
			value:       string(encoded),
			description: "Auto-serialized YAML list (JSON array of strings)",
		})
	case yaml.AliasNode:
		if path != "" {
			*skipped = append(*skipped, path)
		}
	}
	return nil
}

// isRecoveryKit reports whether the file begins with the SECREVOKIT01
// magic header documented in recovery_kit.go. We don't validate the
// rest of the header here; the decrypt step does that with a real
// passphrase.
func isRecoveryKit(raw []byte) bool {
	return len(raw) >= kitMagicLen && string(raw[:kitMagicLen]) == kitMagic
}

// importLeavesFromRecoveryKit decrypts a kit blob, unmarshals the
// embedded exportPayload, and converts each entry to an importLeaf so
// the rest of the import pipeline (dry-run, create-or-rotate, skip-
// existing) treats it the same as a YAML walk.
func importLeavesFromRecoveryKit(cmd *cobra.Command, opts Options, blob []byte) ([]importLeaf, error) {
	passphrase, err := resolveKitPassphrase(cmd, opts)
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptRecoveryKit(blob, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypt recovery kit: %w", err)
	}
	var payload exportPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("parse decrypted kit JSON: %w", err)
	}
	leaves := make([]importLeaf, 0, len(payload.Secrets))
	for _, s := range payload.Secrets {
		leaves = append(leaves, importLeaf{
			name:        s.Name,
			value:       s.Value,
			description: s.Description,
		})
	}
	return leaves, nil
}

// resolveKitPassphrase returns the kit passphrase from exactly one of
// --passphrase / --passphrase-file / --passphrase-from-stdin. Trailing
// whitespace is trimmed so a passphrase file written by
// `secrevo export --kit` (which has no trailing newline) round-trips
// the same as one a human created with a trailing newline.
func resolveKitPassphrase(cmd *cobra.Command, opts Options) (string, error) {
	literal, _ := cmd.Flags().GetString("passphrase")
	filePath, _ := cmd.Flags().GetString("passphrase-file")
	fromStdin, _ := cmd.Flags().GetBool("passphrase-from-stdin")

	provided := 0
	if literal != "" {
		provided++
	}
	if filePath != "" {
		provided++
	}
	if fromStdin {
		provided++
	}
	if provided == 0 {
		return "", fmt.Errorf("recovery kit import requires a passphrase: pass --passphrase, --passphrase-file PATH, or --passphrase-from-stdin")
	}
	if provided > 1 {
		return "", fmt.Errorf("--passphrase, --passphrase-file, and --passphrase-from-stdin are mutually exclusive")
	}
	if literal != "" {
		return literal, nil
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read passphrase file %s: %w", filePath, err)
		}
		return strings.TrimRight(string(data), "\r\n \t"), nil
	}
	stdin := opts.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return "", fmt.Errorf("read passphrase from stdin: %w", err)
	}
	return strings.TrimRight(string(data), "\r\n \t"), nil
}

// scalarSequence reports whether every child of a SequenceNode is a
// ScalarNode and returns the collected string values. Returns false on
// the first non-scalar child so the caller can fall back to skipping.
func scalarSequence(node *yaml.Node) ([]string, bool) {
	values := make([]string, 0, len(node.Content))
	for _, child := range node.Content {
		if child.Kind != yaml.ScalarNode {
			return nil, false
		}
		values = append(values, child.Value)
	}
	return values, true
}

func joinPath(parent, child, separator string) string {
	child = strings.TrimSpace(child)
	if parent == "" {
		return child
	}
	return parent + separator + child
}

// ensureImportNotEmpty is exposed for tests that want to invoke runImport
// programmatically without going through cobra wiring. It's a thin wrapper
// around the package-private walker.
func ensureImportNotEmpty(yamlBytes []byte, prefix, separator string) ([]importLeaf, []string, error) {
	_ = context.Background()
	var doc yaml.Node
	if err := yaml.Unmarshal(yamlBytes, &doc); err != nil {
		return nil, nil, err
	}
	return flattenYAML(&doc, prefix, separator)
}
