resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_access_rule" "literal_only" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "LITERAL-ONLY"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true
  source_network_literals {
    literal { value = "10.10.0.0/24" }
  }
  destination_network_literals {
    literal { value = "10.20.0.0/24" }
  }
}
