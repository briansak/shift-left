# FMC provider credentials are injected at deploy time via TF_VAR_* (see scripts/deploy_fmc.py).
# TODO: confirm provider block attribute names for your CiscoDevNet/fmc provider version.

provider "fmc" {
  url      = "https://${var.fmc_host}"
  username = var.fmc_username
  password = var.fmc_password
  insecure = var.fmc_insecure # TODO: set false when lab FMC has a trusted CA
}
