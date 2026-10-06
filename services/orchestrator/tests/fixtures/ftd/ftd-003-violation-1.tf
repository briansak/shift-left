resource "fmc_access_policy" "branch" {
  name = "branch-policy"
}

resource "fmc_access_rule" "allow_internet_inbound" {
  access_control_policy_id = fmc_access_policy.branch.id
  name             = "ALLOW-INTERNET-INBOUND"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = false

  source_network_literals {
    literal {
      value = "0.0.0.0/0"
    }
  }
}
