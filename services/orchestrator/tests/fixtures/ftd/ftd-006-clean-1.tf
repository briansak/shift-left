resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_access_rule" "allow_https" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "ALLOW-HTTPS"
  action           = "ALLOW"
  enabled          = true
}

resource "fmc_access_rule" "deny_rest" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "DENY-REST"
  action           = "BLOCK"
  enabled          = true
  source_network_literals {
    literal {
      value = "0.0.0.0/0"
    }
  }
}
