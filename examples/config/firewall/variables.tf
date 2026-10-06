variable "fmc_host" {
  description = "FMC hostname or IP (no scheme)"
  type        = string
}

variable "fmc_username" {
  description = "FMC API user"
  type        = string
  sensitive   = true
}

variable "fmc_password" {
  description = "FMC API password"
  type        = string
  sensitive   = true
}

variable "fmc_insecure" {
  description = "Skip TLS verification (lab only)"
  type        = bool
  default     = true
}

variable "policy_name" {
  description = "Access policy name managed by this stack"
  type        = string
  default     = "branch-edge-access"
}
