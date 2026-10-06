resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_access_rule" "missing_dest" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "MISSING-DEST"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true
  source_network_literals {
    literal { value = "10.0.0.0/8" }
  }
  destination_network_literals {
    literal { value = "any" }
  }
}
