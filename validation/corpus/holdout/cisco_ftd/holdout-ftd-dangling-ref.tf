resource "fmc_access_policy" "holdout_refs" {
  name = "holdout-ref-policy"
}

resource "fmc_network" "known_segment" {
  name  = "KNOWN-SEGMENT"
  prefix = "198.18.20.0/24"
}

resource "fmc_access_rule" "unknown_partner_net" {
  access_control_policy_id = fmc_access_policy.holdout_refs.id
  name             = "UNKNOWN-PARTNER-NET"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true
  source_network_objects {
    objects { id = fmc_network.partner_missing.id type = "Network" }
  }
  destination_network_objects {
    objects { id = fmc_network.known_segment.id type = "Network" }
  }
}
