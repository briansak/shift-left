# dCloud lab — ftdv-10.0.0-140-preconfig

Default networking for the **Cisco dCloud** FTDv pod used with Shift-Left. Machine-readable profile: [`config/dcloud-vm.profile.yaml`](../config/dcloud-vm.profile.yaml).

## VM summary

| Field | Value |
|-------|--------|
| Profile | `ftdv-10.0.0-140-preconfig` |
| Created | 20260406 |
| Management IP | `198.18.134.100` (DHCP, adapter 0) |
| Default gateway | `198.18.128.1` |
| Primary DNS | `198.18.128.1` |
| Secondary DNS | `1.1.1.1` |

Store FMC/FTD login credentials in **local** `terraform.tfvars` or environment variables only — never commit them to git. Use the dCloud session catalog for the pod’s default admin password and rotate after first login.

## Networks

| Name | Routed by vPodGW | CIDR |
|------|------------------|------|
| Default Network | Yes | `198.18.128.0/18` |
| Private | No | `198.18.10.0/24` |

## Adapters

| Adapter | Network | IP | DHCP |
|---------|---------|-----|------|
| 0 | Default Network | `198.18.134.100` | Yes |
| 1 | Private | `198.18.10.1` | No |
| 2 | Private | (unassigned) | No |
| 3 | Private | (unassigned) | No |

Adapter 0 carries **management** (Default Network / vPodGW). Adapter 1 is the primary **inside/data** interface on the Private segment. Adapters 2–3 are spare Private NICs for lab expansion.

## Terraform mapping

| dCloud concept | Terraform variable / file |
|----------------|---------------------------|
| Device name in FMC | `ftd_device_name` → `ftdv-10.0.0-140-preconfig` |
| Outside / vPodGW | `default_network_cidr` → `198.18.128.0/18` |
| Inside / Private | `private_network_cidr` → `198.18.10.0/24` |
| Inside interface IP | `private_interface_ip` → `198.18.10.1` (reference; set on device at deploy) |
| Access policy rules | `terraform/policies/rules_dcloud_data.tf` |

Interface IP/DHCP on the FTDv itself is normally configured at **first boot or FMC device setup**. Terraform here manages **FMC objects** (policy, rules, assignment). See `terraform/device/dcloud-interfaces.tf.example` for a provider-specific interface template.

## Quick start

This example pins **CiscoDevNet/fmc `2.0.1`**, matching Shift-Left handler validation (`validation/schemas/fmc-2.0.1-schema.json`).

```bash
cd examples/ftdv-firewall/terraform
cp terraform.tfvars.example terraform.tfvars
# Set fmc_host + API credentials for your dCloud FMC
terraform init && terraform plan
```

Shift-Left local check (no FMC apply):

```bash
./examples/ftdv-firewall/scripts/analyze-local.sh
```
