resource "fmc_access_rule" "inside_any_dest" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name             = "INSIDE-ANY-DEST"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals = [{ value = "10.0.0.0/8" }]
  destination_network_literals = [{ value = "any" }]
}
