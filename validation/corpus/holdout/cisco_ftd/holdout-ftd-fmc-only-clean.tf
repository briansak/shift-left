resource "fmc_access_policy" "holdout" {
  name = "holdout-clean"
}

resource "fmc_access_rule" "scoped_allow" {
  access_control_policy_id     = fmc_access_policy.holdout.id
  name                 = "SCOPED-ALLOW"
  action               = "ALLOW"
  enabled              = true
  log_connection_begin = true
  source_network_literals {
    literal { value = "198.18.10.0/24" }
  }
  destination_network_literals {
    literal { value = "198.18.20.0/24" }
  }
}
