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

variable "environment" {
  description = "Short environment label (lab, staging, prod)"
  type        = string
  default     = "dcloud"
}

variable "policy_name" {
  description = "FMC access policy name for this FTDv stack"
  type        = string
  default     = "ftdv-dcloud-default"
}

variable "ftd_device_name" {
  description = "Registered FTDv device name in FMC (dCloud preconfig profile)"
  type        = string
  default     = "ftdv-10.0.0-140-preconfig"
}

# --- dCloud ftdv-10.0.0-140-preconfig networking (see config/dcloud-vm.profile.yaml) ---

variable "default_network_cidr" {
  description = "Default Network — routed by vPodGW (outside / lab transit)"
  type        = string
  default     = "198.18.128.0/18"
}

variable "private_network_cidr" {
  description = "Private Network — inside segment (adapter 1+)"
  type        = string
  default     = "198.18.10.0/24"
}

variable "private_interface_ip" {
  description = "Static inside IP on adapter 1 (reference for lab docs)"
  type        = string
  default     = "198.18.10.1"
}

variable "management_ip" {
  description = "FTDv management IP on Default Network (adapter 0, DHCP in dCloud)"
  type        = string
  default     = "198.18.134.100"
}

variable "default_gateway" {
  description = "Lab default gateway (vPodGW)"
  type        = string
  default     = "198.18.128.1"
}

variable "primary_dns" {
  description = "Primary DNS server"
  type        = string
  default     = "198.18.128.1"
}

variable "secondary_dns" {
  description = "Secondary DNS server"
  type        = string
  default     = "1.1.1.1"
}

variable "lab_admin_source_cidr" {
  description = "Source CIDR for scoped SSH into the Private segment from the lab"
  type        = string
  default     = "198.18.128.0/18"
}
