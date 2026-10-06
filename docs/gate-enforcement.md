# Gate enforcement

This document is for operators who need the merge gate to mean something. It covers commit status, registry severity, waivers, and what the gate will not do. HTTP: [api-guide.md](api-guide.md). Parser scope: [supported-platforms.md](supported-platforms.md).

Shift-Left publishes a deployment gate as a commit status on the PR head SHA. Branch protection on the git host is what turns that status into merge control; the workflow file alone does not.

## What the gate does

- Evaluates the **policy decision** for a specific commit SHA (using deterministic `policy_severity`, not model-asserted labels).
- Requires a **human approval** bound to the same commit SHA.
- When `policy.allow_block_override` is false, a **block** decision cannot be bypassed.
- When override is enabled, bypass requires an **override-capable API token**, explicit justification, and an audit event.
- Publishes a commit status (default context: `shift-left/gate`) on the head SHA via the configured git backend (Forgejo by default).
- PR comments list **deterministic handler findings only** and do not post model `review_summary`. Foundation-Sec and Antares findings remain in the Shift-Left UI. `POST /api/v1/review` omits the same advisory findings when `advisory_suppression.omit_from_review_api` is true (default). `omit_from_pr_comments` is the matching switch for Forgejo comments.

## Registry severity and operator escalation

Each enabled registry rule has severity `block` or `flag`. That value is the **floor** for the gate action on that finding:

- `flag` rules never drop below FLAG, even if a broad CWE policy would have been silent
- `block` rules with blocking `policy_severity` (high/critical) floor at BLOCK

YAML `policy.operator_escalations` may raise a specific `rule_id` to BLOCK. There is no config switch that silently downgrades a `block` rule to pass.

```yaml
policy:
  operator_escalations:
    - rule_id: FTD-002
      action: block
```

## What the gate does not guarantee

- It is **not** a compliance verdict. Findings and policy decisions remain advisory.
- It does **not** scan live infrastructure — only supplied diff/config text.
- It does **not** prevent a malicious actor with repo admin rights from disabling branch protection or removing required checks.
- It does **not** replace code review; separation-of-duties rules reduce self-approval but require correct git author metadata.

**Branch protection** is what converts the gate from a suggestion into a merge-blocking control.

## Required Forgejo branch protection settings

Configure these on the protected branch (e.g. `main`) in Forgejo:

1. **Protected branch** — enable protection for the target branch.
2. **Require pull request** — merges must go through a PR (required reviews ≥ 1).
3. **Required status checks** — enable status checks and add exactly:
   - `shift-left/gate` (or your configured `gate.status_context`)
4. **Dismiss stale approvals** — recommended so new commits invalidate prior approvals (Shift-Left also invalidates approvals bound to old SHAs).
5. **Restrict pushes** — limit who can push directly to the protected branch.

Exact UI path (Forgejo 11.x): **Repository → Settings → Branches → Edit rule** for `main`:

| Setting | Value |
|--------|--------|
| Enable branch protection | ✓ |
| Require signed commits | org policy (optional) |
| Require pull request | ✓ |
| Required approvals | ≥ 1 |
| Require status checks to pass | ✓ |
| Status checks that are required | `shift-left/gate` |
| Restrict pushes | ✓ (recommended) |

## Orchestrator self-check

Set `gate.check_repo` to an `owner/repo` slug the orchestrator can query. On startup / `/self-check`, Shift-Left warns if the protected branch does **not** list `gate.status_context` as a required check.

```yaml
gate:
  enabled: true
  protected_branch: main
  status_context: shift-left/gate
  publish_commit_status: true
  warn_if_branch_protection_missing: true
  check_repo: shift-left/example-app
```

## CI workflow vs commit status

A workflow step that calls `/api/v1/gate` can be removed in the same PR. The **commit status** is published independently on the head SHA. With branch protection requiring `shift-left/gate`, merges are blocked even if the workflow file is edited or deleted.

## API tokens

State-changing API calls require bearer tokens (`Authorization: Bearer slt_…`). Actor identity is derived from the token — client-supplied `approver` / `actor` fields are rejected. See `docs/auth-tokens.md`.

## Uninterpretable content (CWE-657 and CWE-754)

**Decision: both block the gate.**

Shift-Left treats “content the gate cannot interpret” as merge-blocking. Two handler CWEs cover the cases:

| CWE | Source | Meaning |
|-----|--------|---------|
| **CWE-657** | `gate.unclaimed_files` | A changed file path is not matched by `routing.code_globs` or `routing.config_globs` (and not in `routing.pr_gate_exclusion_globs`). No deterministic handler runs on the file. |
| **CWE-754** | ASA-007 (ASA ACL), IOS-001 / IOS-010 (IOS-XE CLI), NXOS-001 / NXOS-002 (NX-OS CLI), HCL-001 (HCL/Terraform), CLI-001 (undeclared CLI) | A line or file the gate cannot interpret. ASA: unparsed ACE or undefined object-group. IOS-XE: unparsed ACE/CLI line or undefined object-group (IOS-001); declared vs sniffed platform mismatch (IOS-010). NX-OS: unparsed ACL/CLI line or undefined object-group (NXOS-001); declared vs sniffed platform mismatch (NXOS-002). HCL: `python-hcl2` missing, syntax error, or other deterministic parse failure on `**/*.tf` / `**/*.hcl` / `**/*.tfvars` for `cisco_ftd` and `generic_terraform` targets. CLI-001: an undeclared file whose platform cannot be determined from content. |

Both map to `policy_severity=high` and match default BLOCK policies (`block-unclaimed-changed-files`, `block-uninterpretable-config`). Registry rule severity for ASA-007, IOS-001, IOS-010, NXOS-001, NXOS-002, HCL-001, and CLI-001 is `block`.

**Waivability.** ASA-007, IOS-001, IOS-010, NXOS-001, NXOS-002, and HCL-001 are registered registry rules with `waivable=true`. A BLOCK-level finding on those rules can be waived with an **approve**-capability token (triage is insufficient). Waiver **identity** is `(repo, pr_ref, target_kind, file_path, construct_key, weakness_class)` — path + parsed construct + handler CWE, not line numbers. `line_start` is stored for display only. A new commit SHA invalidates prior waivers. CWE-657 (unclaimed paths) is **not** waivable — remediation is routing scope change or explicit exclusion. CLI-001 is registered with `waivable=false` and is **not** waivable — remediation is a `managed_targets.targets` entry with a declared `target_type`.

Construct keys by target type:

| Target | Construct key |
|--------|----------------|
| ASA / cisco_secure_firewall | ACE `ace:{acl}:{normalized raw}`; named object `object:{name}`; crypto `crypto:{kind}:{name}`; unparsed line `unparsed:{raw}`; management `mgmt:{service}:{network}:{mask}:{interface}` |
| FTD / cisco_ftd | FMC rule `rule:{name}:seq:{n}`; resource `resource:{type}.{name}` (port object, IKEv2 policy) |
| IOS-XE | ACE `ace:{acl}:{raw}`; directive `directive:{raw or canonical name}`; interface `interface:{name}`; VTY `line:{type}:{marker}`; unparsed/unresolved as above; platform mismatch `file` |
| NX-OS | ACE / directive / unparsed as IOS-XE; feature `feature:{name}`; role `role:{name}`; platform mismatch `file` |
| Terraform / HCL | Resource `resource:{type}.{name}`; uninterpretable file `file`; uncovered provider `provider:{prefix}` |
| Code handlers | Regex snippet `snippet:{normalized match}` |
| Unclaimed (CWE-657) | `file` (not waivable) |

**Uncovered HCL providers (HCL-002 / FTD-009).** When a claimed `.tf` / `.hcl` file parses successfully but contains `resource` types whose provider prefix (`aws_`, `azurerm_`, `google_`, `fmc_`) is outside the enabled rule set for the target type, the gate emits a **FLAG** (not BLOCK) finding naming the uncovered prefix. This closes the silent-pass gap where parseable but unevaluated providers previously yielded zero findings and PASS. Covered prefixes for `generic_terraform`: `aws_`, `azurerm_`, `google_`, `fmc_`. For `cisco_ftd`: `fmc_` only.

**Parser scope.** `routing.routing_parser_claim_globs` (legacy alias `deterministic_parser_globs`) is the set of extensions claimable on the PR path without a managed target. A path matching `config_globs` but not parser scope (e.g. `**/*.cfg` on an ASA target) is classified **unclaimed** (CWE-657). CWE-754 blocks only parser-scoped extensions. IOS-XE and NX-OS also claim `**/*.cfg` via per-target parser scope — see [supported-platforms.md](supported-platforms.md).

**Path claim precedence** (when multiple routing globs match): `pr_gate_exclusion_globs` → `config_globs` ∧ `deterministic_parser_globs` (deterministic config gate; authoritative) → `code_globs` (advisory Antares path) → `config_globs` without parser scope (unclaimed) → otherwise unclaimed. A file matching both `code_globs` and parser-scoped `config_globs` (e.g. `**/*.tf` in both lists) is **config-claimed** and must pass the deterministic gate; code review may still run advisory triage but cannot bypass BLOCK.

**Why two CWEs if both block?** CWE-657 is a *scope* violation (the file was never in the review contract). CWE-754 is a *coverage* gap within scope (the file is claimed but a specific statement is opaque). The remediation differs: claim or exclude the path (657) vs rewrite the ACL or extend parser coverage (754).

## FMC network resolution: `has_no_constraint` asymmetry (FTD-005 vs FTD-006)

FTD rules share the same FMC network resolver (`resolve_endpoint` / `RuleNetworkResolution`) but apply different semantics to an endpoint with **no literals and no object references** (`has_no_constraint=True`):

| Rule | Treats unconstrained endpoint as… | Rationale |
|------|-----------------------------------|-----------|
| **FTD-005** (management exposure) | **Exposed** — fires when source has no network constraint | An ALLOW to management ports with no source network specified is treated as reachable from any source (fail-closed for admin-plane exposure). |
| **FTD-006** (shadowed ALLOW) | **Not catch-all** — does not count toward catch-all BLOCK | A BLOCK with only port/protocol constraints and no network fields is *not* a deny-any-any; only endpoints that **resolve to** `any` / `0.0.0.0/0` (literal or via objects) qualify as catch-all. |

This asymmetry is intentional: FTD-005 guards administrative exposure where omission of source is high risk; FTD-006 models ordered rule shadowing where a port-scoped BLOCK must not shadow unrelated ALLOW rules above it.

## ASA-007: unresolvable object references (CWE-754)

An ACE that references a **network or service** object or object-group that is not defined in the file (or cannot be resolved due to circular/depth errors) is **unresolvable** and emits ASA-007. The resolver does **not** assume unresolved references are narrow — absence of a definition is a coverage gap, not an implicit deny.

This applies equally to:

- undefined **network** object-groups on `permit ip object-group …` ACEs;
- undefined **service** object-groups on `permit object-group …` ACEs;
- undefined network objects on `permit object <service> … object <net>` ACEs.

Complete the snippet with the missing object definitions, or rewrite the ACE to use literals. Other rules (e.g. ASA-002 on service object-groups) evaluate only when resolution succeeds; an undefined service group produces ASA-007, not silence from both rules.

## NXOS-001: NX-OS ACL parse scope (CWE-754)

**Decision: deliberate scope, not a silent-pass gap.**

The NX-OS structural parser tokenizes ACEs only inside **`ip access-list <name>`** configuration blocks (sequence-numbered permit/deny lines under the block header). This matches the dominant NX-OS operational form for named extended ACLs used with VRF contexts, object-groups, and role-based access.

**Out of scope (by design):** standalone top-level `access-list …` one-liners (legacy numbered ACL syntax without a block header). Those lines are counted as ACL-bearing in parse-coverage metrics but stored as **unparsed** and emit **NXOS-001** (`handler:NXOS-001`, CWE-754, registry severity `block`). The gate **blocks** — unparsed content does not silently PASS.

**In scope:** `ip access-list` block ACEs, `object-group ip address` / `object-group ip port` members (with nesting and circular-reference detection), `feature` / `line` / `role` / `vrf context` blocks, and other constructs covered by NXOS-003–NXOS-010.

**Remediation for NXOS-001 on standalone `access-list`:** rewrite as an `ip access-list <name>` block with sequence numbers, or extend parser coverage if a deployment baseline requires legacy numbered ACL syntax.

## HCL-001: uninterpretable HCL/Terraform (CWE-754)

Before any FTD or generic Terraform registry rule runs, the gate checks whether `python-hcl2` can load the file. If the parser is missing or `hcl2.loads()` fails, the gate emits **HCL-001** (`handler:HCL-001`) and stops — it does not silently PASS with zero findings.

HCL-001 is enforced via a pre-match interpretability check in `registry_matching` (not the normal per-rule parser loop). The registry entry exists so waivers, traces, and operator docs treat it like ASA-007: waivable with approve capability, SHA-bound, finding remains visible with a WAIVED pill when waived.
