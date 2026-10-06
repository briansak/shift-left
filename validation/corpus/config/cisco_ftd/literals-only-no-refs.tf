resource "fmc_access_rule" "literal_only" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name             = "LITERAL-ONLY"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals = [{ value = "10.10.0.0/24" }]
  destination_network_literals = [{ value = "10.20.0.0/24" }]
}
