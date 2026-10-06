resource "fmc_access_policy" "branch" {
  name = "branch-policy"
}

resource "fmc_access_rule" "mgmt_https_public" {
  access_control_policy_id = fmc_access_policy.branch.id
  name             = "MGMT-HTTPS-PUBLIC"
  action           = "ALLOW"
  enabled          = true

  source_network_literals {
    literal {
      value = "203.0.113.0/24"
    }
  }

  destination_port_literals {
    literal {
      protocol = "6"
      port     = "443"
    }
  }
}
