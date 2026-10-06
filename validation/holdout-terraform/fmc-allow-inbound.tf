resource "fmc_access_rule" "allow_internet_inbound" {
  access_control_policy_id = fmc_access_policy.branch.id
  name             = "ALLOW-INTERNET-INBOUND"
  action           = "ALLOW"
  enabled          = true

  source_network_literals {
    literal {
      value = "0.0.0.0/0"
    }
  }

  destination_network_literals {
    literal {
      value = "any"
    }
  }

  destination_port_literals {
    literal {
      value = "any"
    }
  }
}
