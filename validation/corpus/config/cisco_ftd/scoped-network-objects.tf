resource "fmc_network" "inside" {
  name  = "INSIDE"
  prefix = "10.0.0.0/8"
}

resource "fmc_network" "dmz" {
  name  = "DMZ"
  prefix = "10.20.0.0/24"
}

resource "fmc_access_rule" "inside_to_dmz" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name             = "INSIDE-TO-DMZ-OBJECTS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_objects = [{ id = fmc_network.inside.id, type = "Network" }]
  destination_network_objects = [{ id = fmc_network.dmz.id, type = "Network" }]
}
