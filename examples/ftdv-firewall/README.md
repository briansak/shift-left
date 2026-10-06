# FTDv firewall config (FMC Terraform)

Terraform project for **Cisco Secure Firewall FTDv** managed through **FMC**, with a **dCloud default profile** (`ftdv-10.0.0-140-preconfig`). Push to Forgejo and review with Shift-Left.

## dCloud lab (default)

| Item | Value |
|------|--------|
| Device | `ftdv-10.0.0-140-preconfig` |
| Mgmt (adapter 0) | `198.18.134.100` DHCP on Default Network |
| Inside (adapter 1) | `198.18.10.1` on Private `198.18.10.0/24` |
| Outside / vPodGW | Default Network `198.18.128.0/18`, gateway `198.18.128.1` |

Details: [`docs/dcloud-lab.md`](docs/dcloud-lab.md) · profile: [`config/dcloud-vm.profile.yaml`](config/dcloud-vm.profile.yaml)

```bash
cd terraform && cp terraform.tfvars.example terraform.tfvars
# Set fmc_host + API password locally (never commit)
```

## Layout

```
config/dcloud-vm.profile.yaml   VM adapter + network reference
docs/dcloud-lab.md              dCloud quick reference
terraform/
  networks/dcloud.tf            Segment documentation
  policies/                     dCloud-scoped access rules
  device/                       Policy assignment + interface template
  lab/                          Weak-rule fixtures for Shift-Left demos
scripts/analyze-local.sh
```

Shift-Left routes `**/*.tf` through Foundation-Sec (deterministic handler rules + optional GGUF model). See `config/shift-left.example.yaml` `routing.config_globs`.

## Prerequisites

- FMC reachable from your workstation (lab)
- FTDv registered in FMC (`ftd_device_name` in tfvars)
- Shift-Left stack running locally (orchestrator + Foundation-Sec)
- Forgejo repo for PR-based reviews (optional but recommended)

Shift-Left handler validation and this example pin **CiscoDevNet/fmc `2.0.1`** (see `validation/schemas/fmc-2.0.1-schema.json`).

## Configure

```bash
cd examples/ftdv-firewall/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit FMC host, credentials, device name, CIDRs
```

Deploy (operator action — not Shift-Left):

```bash
terraform init
terraform plan
terraform apply
```

Credentials via `terraform.tfvars` or `TF_VAR_fmc_password` — never commit secrets.

## Shift-Left: local analysis (no PR)

Evaluate the whole tree without touching FMC:

```bash
# Terminal 1 — scripted engine (no GGUF) or real Foundation-Sec on :8091
export FOUNDATION_SEC_ENGINE=scripted
cd services/foundation-sec-server && foundation-sec-server

# Terminal 2
./examples/ftdv-firewall/scripts/analyze-local.sh
```

Findings include handler-asserted CWEs (e.g. `0.0.0.0/0` + `ALLOW` → CWE-284). The dCloud default rules use scoped `198.18.x` CIDRs and should stay clean.

To test detections, uncomment fixtures in `terraform/lab/shift-left-fixtures.tf.example` (or paste into a throwaway `.tf` file) and re-run `analyze-local.sh`.

## Shift-Left: PR review (Forgejo)

1. Create a Forgejo repo (e.g. `shift-left/ftdv-firewall`) and push this directory.
2. Mint a review token: `./scripts/shift-left token mint --label ftdv-ci --actor ci --capabilities review`
3. Add Forgejo secret `SHIFT_LEFT_TOKEN` with the `slt_…` value.
4. Copy `.forgejo/workflows/shift-left-review.yml` (already included).
5. Open a PR changing Terraform; the workflow calls `POST /api/v1/review`.

Orchestrator fetches the PR diff, sends `.tf` hunks to Foundation-Sec, applies policy, stores findings, and posts an advisory PR comment.

## Related examples

- `examples/config/firewall/` — minimal vulnerable FMC demo (superseded by this project for day-to-day work)
- `examples/demo-repo/` — Python code review demo

## TODO (your lab)

- [ ] Pin `CiscoDevNet/fmc` provider to the version tested against your FMC
- [ ] Set `fmc_insecure = false` when FMC has a trusted TLS certificate
- [ ] Confirm `data.fmc_device` and `fmc_policy_assignment` attribute names for your provider version
- [ ] Add FMC network/group objects if you prefer object references over inline literals
