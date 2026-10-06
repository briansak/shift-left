# Assign the access policy to an already-registered FTDv in FMC.
# Bootstrap/register the VM separately (FMC UI or one-time CLI reg key), then set ftd_device_name.

data "fmc_device" "ftdv" {
  count = var.ftd_device_name != "" ? 1 : 0
  name  = var.ftd_device_name
}

resource "fmc_policy_assignment" "ftdv_access" {
  count       = var.ftd_device_name != "" ? 1 : 0
  policy_id   = fmc_access_policy.edge.id
  policy_type = "AccessPolicy"
  targets = [{
    id   = data.fmc_device.ftdv[0].id
    type = "Device"
    name = data.fmc_device.ftdv[0].name
  }]
}
