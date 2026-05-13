package app

import (
	"context"
	"fmt"
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

Each scalar leaf becomes a secret named by its dotted path, optionally
prefixed with --prefix. For example, with this file:

  cloudflare:
    secrevo:
      token: cf-token-xyz
      account_id: 007761758105

and ` + "`--prefix cf`" + `, the command creates two secrets:

  cf.cloudflare.secrevo.token
  cf.cloudflare.secrevo.account_id

Non-scalar leaves (lists, anchors, multi-doc) are skipped and reported
in the summary. Numbers and booleans are coerced to their YAML string
form (the secret value type is text). Duplicates within the file abort
the run before any API call.

By default the command rotates already-existing secrets; pass --skip-existing
to leave them alone. --dry-run prints the plan without touching the API.

Examples:

  secrevo import ~/.devvault/secrevo/cloudwatch.yml
  secrevo import ~/.devvault/cloudflare.yml --prefix cloudflare
  secrevo import ~/.devvault/aws.yml --dry-run
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runImport(cmd, opts, args[0])
		},
	}
	cmd.Flags().String("prefix", "", "Prefix prepended to every secret name (joined by '.')")
	cmd.Flags().Bool("dry-run", false, "Print the plan without creating or rotating any secret")
	cmd.Flags().Bool("skip-existing", false, "Skip secrets that already exist instead of rotating their value")
	cmd.Flags().String("separator", ".", "Separator between path components when generating secret names")
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

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	leaves, skipped, err := flattenYAML(&doc, prefix, separator)
	if err != nil {
		return fmt.Errorf("walk %s: %w", path, err)
	}
	if len(leaves) == 0 {
		return fmt.Errorf("no scalar leaves found in %s", path)
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
				Name:  leaf.name,
				Value: leaf.value,
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
	name  string // dotted path, already prefixed
	value string // scalar text content (numbers/bools coerced to string)
}

// flattenYAML walks a yaml.Node tree and returns one importLeaf per scalar
// leaf. Sequences and other non-mapping/non-scalar nodes are recorded in
// ``skipped`` (named by their path) so callers can warn the operator.
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
	case yaml.SequenceNode, yaml.AliasNode:
		if path != "" {
			*skipped = append(*skipped, path)
		}
	}
	return nil
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
