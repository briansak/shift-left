# Supported platforms

This is the operator and contributor reference for the five config target types the deterministic gate can parse. Rule tables are generated from the registry; do not edit them by hand.

Generated from `services/orchestrator/shift_left/handlers/config/rules/registry.py` and `parser_scope.py`. Parser behavior below is documented from the parsers themselves.

Regenerate:

```bash
PYTHONPATH=services/orchestrator:services/shift-left-shared \
  .venv/bin/python scripts/generate_docs.py --platforms
```

Routing and unclaimed-file behavior: [gate-enforcement.md](gate-enforcement.md). How to add a rule: [writing-rules.md](writing-rules.md).

## Undeclared CLI (`CLI-001`)

A config file with no managed target, and no IOS-XE, NX-OS, or ASA markers, does not get findings from every platform. The undeclared path emits **CLI-001** (CWE-754, block, `enforced_prematch`, not waivable). The remedy is declaring a managed target, not a code change and not a waiver.

```yaml
managed_targets:
  targets:
    - id: edge-fw-01
      display_name: edge-fw-01
      target_type: cisco_ios_xe
      repo: owner/repo
      branch: main
      config_paths:
        - "configs/**/*.cfg"
```

`target_type` is `cisco_secure_firewall`, `cisco_ios_xe`, or `cisco_nx_os`. `config_paths` must cover the file. Troubleshooting: [troubleshooting.md](troubleshooting.md).

| Target type | Typical files | Parser package |
|-------------|---------------|----------------|
| `cisco_secure_firewall` | `*.rules`, `*.conf` | `parsers/asa/` |
| `cisco_ftd` | `*.tf`, `*.hcl` | `parsers/ftd/` |
| `cisco_ios_xe` | `*.cfg`, `*.conf`, `*.txt` | `parsers/ios_xe/` |
| `cisco_nx_os` | `*.cfg`, `*.conf`, `*.txt` | `parsers/nx_os/` |
| `generic_terraform` | `*.tf`, `*.hcl`, `*.tfvars` | `parsers/terraform_hcl.py` |

## Cisco ASA (`cisco_secure_firewall`)

**Claimed extensions:** `**/*.rules`, `**/*.conf` (parser globs: `**/*.rules`, `**/*.conf`).

**What the parser understands:** Named and numbered ACLs (`access-list` ACE lines), `object` / `object-group` network and service definitions (including nested `group-object`), `ssh` / `http` / `telnet` management access, and crypto map / IKEv1-IKEv2 blocks used by ASA-004.

**Object and group resolution:** Object and object-group references resolve before any rule runs (depth cap 16, circular-reference detection). ACE source, destination, and service are judged on effective values, not on the literal `object-group` token. Unresolved or circular references are never assumed narrow.

**Unparseable content:** ACL-bearing lines the tokenizer cannot represent, and ACE references to undefined object-groups, emit **ASA-007** (CWE-754, block). Standard ACL one-liners that are not extended ACE form are unparsed. A `.cfg` file on an ASA target is **not** in parser scope — it is unclaimed (CWE-657), not ASA-007.

**Not parsed:** IOS-XE / NX-OS CLI, FMC Terraform, and any path outside `*.rules` / `*.conf`. ASA-003 (permit without logging) exists in the registry as disabled.

| Rule | CWE | Severity | Status | Description |
|------|-----|----------|--------|-------------|
| `ASA-001` | CWE-284 | block | enabled | ASA ACL permits unrestricted any/any traffic. |
| `ASA-002` | CWE-284 | flag | enabled | Service object permits any protocol or unconstrained TCP/UDP. |
| `ASA-003` | CWE-778 | flag | disabled | Permit ACE does not include the log keyword. |
| `ASA-004` | CWE-327 | block | enabled | IKEv2/IPsec proposal uses weak encryption, integrity, or DH group < 14. |
| `ASA-005` | CWE-284 | block | enabled | Management plane access is permitted from non-RFC1918 sources. |
| `ASA-006` | CWE-693 | flag | enabled | Permit ACE is shadowed by a preceding deny ip any any. |
| `ASA-007` | CWE-754 | block | enabled | ASA access-list statement could not be parsed or resolved by the structural ACL parser. |

## Cisco FMC / FTD Terraform (`cisco_ftd`)

**Claimed extensions:** `**/*.tf`, `**/*.hcl` (parser globs: `**/*.tf`, `**/*.hcl`).

**What the parser understands:** CiscoDevNet/fmc provider **2.0.1** resources: `fmc_access_rule`, bulk `fmc_access_rules` items, `fmc_port` / network objects, and IKEv2 policy. Network literals use assignment form (`source_network_literals = [{ value = "..." }]`). `access_control_policy_id` is a literal ID string in corpus fixtures — `fmc_access_policy` is not a 2.0.1 resource.

**Object and group resolution:** Network and port object references on a rule resolve through the FMC symbol table before FTD-001 / FTD-005 / FTD-006 run. An unconstrained endpoint (no literals and no object refs) is treated as exposed for FTD-005 and **not** as catch-all for FTD-006. See [gate-enforcement.md](gate-enforcement.md).

**Unparseable content:** If `python-hcl2` is missing or `hcl2.loads()` fails, **HCL-001** (CWE-754, block) fires and no FTD rule runs. Dangling object refs emit **FTD-008**. Uncovered non-`fmc_` provider prefixes emit **FTD-009** (flag), not a silent pass.

**Not parsed:** Live FMC API state, FTD CLI, ASA `access-list` text, and Terraform resources whose provider prefix is not `fmc_` (those are FTD-009 coverage gaps). FTD-007 (intrusion policy omitted) is disabled in the registry.

| Rule | CWE | Severity | Status | Description |
|------|-----|----------|--------|-------------|
| `FTD-001` | CWE-284 | block | enabled | FMC ALLOW rule uses missing or internet-wide source/destination network literals. |
| `FTD-002` | CWE-284 | flag | enabled | FMC port object permits any protocol or unconstrained TCP/UDP. |
| `FTD-003` | CWE-778 | flag | enabled | FMC access rule ALLOW has no connection logging enabled (log_connection_begin / log_connection_end; log_begin accepted as alias). |
| `FTD-004` | CWE-327 | block | enabled | FMC IKEv2 policy uses weak encryption, integrity, or DH group < 14. |
| `FTD-005` | CWE-284 | block | enabled | FMC ALLOW rule exposes management ports to non-RFC1918 sources. |
| `FTD-006` | CWE-693 | flag | enabled | FMC ALLOW rule is shadowed by a catch-all BLOCK in the same fmc_access_rules ordered set (ASA-006 equivalent). |
| `FTD-007` | CWE-693 | flag | disabled | FMC ALLOW rule has no intrusion_policy_id (or legacy intrusion_policy) attached. |
| `FTD-008` | CWE-754 | block | enabled | FMC access rule references a network object resource that is not defined in the same Terraform module. |
| `FTD-009` | CWE-657 | flag | enabled | Terraform resources use a provider prefix that no enabled FTD registry rule evaluates (coverage gap, not a configuration violation). |
| `HCL-001` | CWE-754 | block | enforced_prematch | HCL/Terraform file could not be parsed or python-hcl2 is unavailable — the gate cannot interpret this content (applies to generic_terraform and cisco_ftd). |

## Cisco IOS-XE (`cisco_ios_xe`)

**Claimed extensions:** `**/*.cfg`, `**/*.conf`, `**/*.txt` — `.cfg` is per-target only, not globally claimed (parser globs: `**/*.cfg`, `**/*.conf`, `**/*.txt`).

**What the parser understands:** Global settings, `line` / VTY blocks, `interface` blocks, AAA, SNMP, management services (`ip ssh`, `transport input`), and standard/extended numbered and named ACLs as `AccessListEntry` with line numbers. Parser layout: `parsers/ios_xe/` (`parser.py`, `resolver.py`, `checks.py`).

**Object and group resolution:** `object-group network` and `object-group service` are indexed including nested `group-object`. Resolution runs before rules (depth cap 16, circular detection). There is no literal-only evaluation path.

**Unparseable content:** UNPARSED ACL/config lines and UNRESOLVED object-group refs emit **IOS-001** (CWE-754, block). When the declared target type disagrees with sniffed IOS-XE / NX-OS / ASA markers, **IOS-010** fires (CWE-754, block). Neither declaration nor sniff is trusted silently.

**Not parsed:** NX-OS `ip access-list` block syntax (sniffed as NX-OS → IOS-010), ASA `access-list` extended form on an IOS-XE target, and `.cfg` files when no `cisco_ios_xe` managed target matches — those stay unclaimed (CWE-657) because `**/*.cfg` is omitted from global routing claim globs. IOS-009 (BPDU guard / port-security) is disabled.

| Rule | CWE | Severity | Status | Description |
|------|-----|----------|--------|-------------|
| `IOS-001` | CWE-754 | block | enabled | IOS-XE configuration statement could not be parsed or resolved by the structural CLI parser. |
| `IOS-010` | CWE-754 | block | enabled | Declared managed target_type disagrees with platform sniffed from CLI content. |
| `IOS-002` | CWE-319 | block | enabled | VTY line permits cleartext telnet transport. |
| `IOS-003` | CWE-284 | block | enabled | SNMP uses default community strings or grants read-write access. |
| `IOS-004` | CWE-287 | block | enabled | AAA login is not configured or enable uses reversible type-7 password. |
| `IOS-005` | CWE-319 | block | enabled | Cleartext management is enabled (HTTP server or password encryption disabled). |
| `IOS-006` | CWE-284 | block | enabled | ACL permit ACE allows any resolved source to any resolved destination. |
| `IOS-007` | CWE-693 | flag | enabled | Trunk uses native VLAN 1 or negotiates DTP in auto/desirable mode. |
| `IOS-008` | CWE-284 | block | enabled | VTY access-class ACL permits non-RFC1918 sources. |
| `IOS-009` | CWE-693 | flag | disabled | Access port lacks BPDU guard and port-security hardening. |

## Cisco NX-OS (`cisco_nx_os`)

**Claimed extensions:** `**/*.cfg`, `**/*.conf`, `**/*.txt` — `.cfg` is per-target only (parser globs: `**/*.cfg`, `**/*.conf`, `**/*.txt`).

**What the parser understands:** `ip access-list <name>` configuration **blocks** (sequence-numbered permit/deny), `object-group ip address` / `object-group ip port` with nesting, `feature`, `line`, `role`, and `vrf context` blocks covered by NXOS-003–NXOS-010.

**Object and group resolution:** Object-group members resolve with nesting and circular-reference detection before NXOS-003 (any-any) and related rules run. Unresolved groups emit NXOS-001.

**Unparseable content:** Standalone top-level `access-list …` one-liners (legacy numbered ACL syntax without a block header) are counted as ACL-bearing for parse-coverage metrics but stored as unparsed and emit **NXOS-001** (CWE-754, block) **by design**. They do not silently PASS. Declared vs sniffed platform mismatch emits **NXOS-002**.

**Not parsed:** IOS-XE CLI, ASA `access-list` extended form, and NX-OS features outside the blocks listed above. Rewrite standalone `access-list` lines as `ip access-list <name>` with sequence numbers, or accept NXOS-001 / waive with approve.

| Rule | CWE | Severity | Status | Description |
|------|-----|----------|--------|-------------|
| `NXOS-001` | CWE-754 | block | enabled | NX-OS configuration statement could not be parsed or resolved by the structural CLI parser. |
| `NXOS-002` | CWE-754 | block | enabled | Declared managed target_type disagrees with platform sniffed from CLI content. |
| `NXOS-003` | CWE-319 | block | enabled | Cleartext telnet feature is enabled on the management plane. |
| `NXOS-004` | CWE-287 | block | enabled | SSH feature is disabled or absent while VTY lines are configured. |
| `NXOS-005` | CWE-284 | block | enabled | SNMP uses default community strings or grants read-write access. |
| `NXOS-006` | CWE-287 | block | enabled | AAA login authentication is not configured for VTY access. |
| `NXOS-007` | CWE-284 | block | enabled | Role definition grants broad permit command * privilege. |
| `NXOS-008` | CWE-284 | block | enabled | Management VRF VTY access-class permits sources outside RFC1918 space. |
| `NXOS-009` | CWE-284 | block | enabled | ACL permit ACE allows any resolved source to any resolved destination. |
| `NXOS-010` | CWE-319 | block | enabled | Unencrypted file-transfer feature (FTP, TFTP, or SCP-server) is enabled. |

## Generic Terraform (`generic_terraform`)

**Claimed extensions:** `**/*.tf`, `**/*.hcl`, `**/*.tfvars` (parser globs: `**/*.tf`, `**/*.hcl`, `**/*.tfvars`).

**What the parser understands:** HCL resource blocks parsed with `python-hcl2`. TF-001 evaluates internet-wide ingress on AWS / Azure / GCP security-group style resources. FMC resources in a generic_terraform target are handled as uncovered providers (HCL-002) unless they match TF-001.

**Object and group resolution:** No network object-group table. CIDRs and `0.0.0.0/0` are read from resource attributes. Provider prefix is taken from the resource type (`aws_`, `azurerm_`, `google_`, `fmc_`).

**Unparseable content:** Missing `python-hcl2` or HCL syntax errors emit **HCL-001** (CWE-754, block) and stop. Successfully parsed files whose resource prefixes are outside the enabled rule set emit **HCL-002** (CWE-657, flag) so parseable-but-unevaluated providers cannot silent-pass.

**Not parsed:** Providers other than `aws_`, `azurerm_`, `google_`, and `fmc_` (HCL-002). FMC-specific FTD-00x checks do not run on `generic_terraform` — use target_type `cisco_ftd` for those. `.tfvars` is in parser scope; interpretability still requires valid HCL.

| Rule | CWE | Severity | Status | Description |
|------|-----|----------|--------|-------------|
| `TF-001` | CWE-284 | block | enabled | Terraform resource allows internet-wide ingress (0.0.0.0/0 or equivalent). |
| `HCL-001` | CWE-754 | block | enforced_prematch | HCL/Terraform file could not be parsed or python-hcl2 is unavailable — the gate cannot interpret this content (applies to generic_terraform and cisco_ftd). |
| `HCL-002` | CWE-657 | flag | enabled | Terraform resources use a provider prefix that no enabled registry rule evaluates (coverage gap, not a configuration violation). |
