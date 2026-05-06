# getsecrevo/cli

`cli` is the operator-facing command line client for the **secrevo** product.
It is a Cat C product repo: product code that consumes the Secrevo API
contract and helps humans, CI jobs, and future automation drive the platform
from a local workspace.

## Purpose

The CLI provides the first local surface for Secrevo operators and developers.
It is intentionally small and focused: inspect the current identity, bootstrap
a workspace, fetch secret metadata, create agents, and reserve a `run`
command for the future secret-aware execution flow.

The repo does not own storage or business rules. It is a thin client over the
Secrevo API contract and the eventual automation boundary around it.

## Stack

- Go 1.23+
- [Cobra](https://github.com/spf13/cobra) for the command tree
- Standard library `net/http` for API access

## Architecture role

This repo sits at the edge of the product. It translates operator intent into
Secrevo API calls and prints machine-readable output that other tools can
consume.

The CLI depends on the API contract documented in:
- [Secrevo API contract](https://github.com/getsecrevo/api/blob/main/docs/contract.md)
- [OpenAPI draft](https://github.com/getsecrevo/api/blob/main/docs/openapi.yaml)

The API remains the source of truth for auth, workspace, member, agent,
secret, grant, access-request, and audit behavior. The CLI is a consumer, not
the authority.

## Primary consumers

- Developers working on Secrevo locally
- Operators bootstrapping or inspecting workspaces
- Future automation that needs a stable command surface
- CI jobs that need a small, scriptable control plane entrypoint

## API / contract

The initial command surface maps to the documented API contract:

- `secrevo version`
- `secrevo auth whoami`
- `secrevo workspace bootstrap`
- `secrevo secret get <secret-name>`
- `secrevo agent create <name>`
- `secrevo run -- <command>`

The API client uses:

- `SECREVO_API_BASE_URL`
- `SECREVO_API_TOKEN`
- `SECREVO_WORKSPACE_ID` or `--workspace-id` for workspace-scoped commands

The current `run` command is contract-first: it prints the invocation contract
and does not yet execute the target command.

## Local development

```bash
go test ./...
go run ./cmd/secrevo version
SECREVO_API_BASE_URL=http://localhost:8080 \
SECREVO_API_TOKEN=dev-token \
SECREVO_WORKSPACE_ID=workspace-123 \
go run ./cmd/secrevo auth whoami
```

If Go is not installed locally, use the same commands inside a Go container.

## Tests

The repo uses Go unit tests for two layers:

- command parsing and command wiring
- API client request boundaries and config validation

Run the full suite with:

```bash
go test ./...
```

The suite is intentionally small so it can stay fast while the CLI surface is
still being defined.

## Deployment

The CLI is not a server-side deployment target. It is shipped as a Go binary.

Planned delivery model:

- build in CI
- publish release artifacts
- consume the binary locally or in automation

The runtime services remain in `api/` and `infrastructure/`.

## Cross-references

- Governance: <https://github.com/getGanemo/docs-company/blob/main/governance/product-structure.md>
- Product project management: <https://github.com/getsecrevo/project_management>
- API implementation: <https://github.com/getsecrevo/api>
- Infrastructure: <https://github.com/getsecrevo/infrastructure>

