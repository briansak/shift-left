resource "fmc_access_rule" "bad_source_ref" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name             = "BAD-SOURCE-REF"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_objects = [{ id = fmc_network.missing_inside.id, type = "Network" }]
  destination_network_literals = [{ value = "10.20.0.0/24" }]
}
