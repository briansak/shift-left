resource "fmc_access_rule" "allow_https" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name             = "ALLOW-HTTPS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
}

resource "fmc_access_rule" "deny_rest" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name             = "DENY-REST"
  action           = "BLOCK"
  enabled          = true
  source_network_literals = [{ value = "0.0.0.0/0" }]
}
