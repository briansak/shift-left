# FMC manages on-prem FTDv. Credentials via TF_VAR_* or terraform.tfvars (never commit secrets).

provider "fmc" {
  url      = "https://${var.fmc_host}"
  username = var.fmc_username
  password = var.fmc_password
  insecure = var.fmc_insecure # TODO: set false when FMC presents a trusted CA
}
