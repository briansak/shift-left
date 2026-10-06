# Holdout: CiscoDevNet/fmc v2.0.1-style literals with legacy access_policy_id alias.
resource "fmc_access_policy" "holdout_broad" {
  name = "holdout-broad-policy"
}

resource "fmc_access_rule" "partner_any_source" {
  access_control_policy_id = fmc_access_policy.holdout_broad.id
  name             = "PARTNER-ANY-SOURCE"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true
  source_network_literals {
    literal { value = "any" }
  }
  destination_network_literals {
    literal { value = "10.44.0.0/24" }
  }
}
