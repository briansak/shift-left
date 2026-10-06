# HOLDOUT — FMC access rule with log_connection_begin explicitly disabled (FTD-003)
resource "fmc_access_policy" "holdout_no_log" {
  name = "holdout-no-log"
}

resource "fmc_access_rule" "silent_allow" {
  access_control_policy_id = fmc_access_policy.holdout_no_log.id
  name             = "SILENT-ALLOW"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = false

  source_network_literals {
    literal { value = "10.0.0.0/8" }
  }

  destination_network_literals {
    literal { value = "10.0.0.0/8" }
  }
}
