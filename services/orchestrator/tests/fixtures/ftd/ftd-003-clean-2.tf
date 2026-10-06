resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_access_rule" "default_deny" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "DEFAULT-DENY"
  action           = "BLOCK"
  enabled          = true
  log_connection_begin        = false
}
