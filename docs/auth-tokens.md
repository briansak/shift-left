# API tokens

This is the capability table for Shift-Left API tokens. Operators minting tokens and anyone calling the HTTP API should read it. Request and response shapes: [api-guide.md](api-guide.md).

Actor identity always comes from the token. Tokens are stored hashed (SHA-256 with `SHIFT_LEFT_TOKEN_PEPPER`); plaintext is shown once at mint.

## Capabilities

| Capability | Allows |
|-----------|--------|
| `review` | `POST /api/v1/review` |
| `triage` | Finding status, waivers (non-BLOCK), investigations |
| `approve` | Grant/revoke approvals; BLOCK-level waivers |
| `override` | Block overrides when `policy.allow_block_override` is true |
| `deploy` | Plan-only Terraform (`POST /api/v1/changes/.../plan`) |
| `admin` | All of the above, plus system settings and service lifecycle |

`approve` and `override` are independent. Override cannot approve; approve cannot override a block.

## CLI

```bash
./shift-left token mint --label "alice-approver" --actor alice --capabilities approve
./shift-left token list
./shift-left token revoke --id <token-uuid>
```

Forgejo Actions uses repo secret `SHIFT_LEFT_TOKEN` (a `review`-capable token). `./shift-left up` and `./shift-left new-repo` write that secret. If reviews start failing with 401 after a reset, re-run `up` or mint a new token and update the Forgejo secret.

## HTTP

```http
Authorization: Bearer slt_<secret>
```

Alternatively: `X-Shift-Left-Token: slt_<secret>`

Client-supplied `approver` or `actor` JSON fields are rejected with HTTP 400.

Unauthenticated: `GET /health`, `GET /self-check`. There is no Forgejo webhook listener on the orchestrator. The Antares sandbox callback uses a short-lived `slat_…` token, not a UI session. HTML `/ui/*` uses the login cookie.

There is no `SHIFT_LEFT_OVERRIDE_ACTOR`. Mapping an external IdP onto `actor` at mint time is an operator process; the product does not implement OIDC login.
