resource "fmc_access_rule" "default_deny" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "DEFAULT-DENY-LOG"
  action           = "BLOCK"
  enabled          = true
  log_connection_begin        = true
  log_connection_end          = true
}
