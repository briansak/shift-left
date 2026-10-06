output "access_policy_id" {
  description = "FMC UUID for the managed access policy"
  value       = fmc_access_policy.edge.id
}

output "access_policy_name" {
  value = fmc_access_policy.edge.name
}

output "ftd_device_id" {
  description = "FMC device UUID when ftd_device_name is set"
  value       = try(data.fmc_device.ftdv[0].id, null)
}

output "dcloud_profile" {
  description = "Lab network summary (matches config/dcloud-vm.profile.yaml)"
  value = {
    device_name           = var.ftd_device_name
    management_ip         = var.management_ip
    private_interface_ip  = var.private_interface_ip
    default_network_cidr  = var.default_network_cidr
    private_network_cidr  = var.private_network_cidr
    default_gateway       = var.default_gateway
    primary_dns           = var.primary_dns
    secondary_dns         = var.secondary_dns
  }
}
