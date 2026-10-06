resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_access_rule" "internet_ingress" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INTERNET-INGRESS"
  action           = "ALLOW"
  enabled          = true
  source_network_literals {
    literal { value = "0.0.0.0/0" }
  }
}
