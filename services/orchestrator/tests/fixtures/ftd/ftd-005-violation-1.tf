resource "fmc_access_policy" "branch" {
  name = "branch-policy"
}

resource "fmc_access_rule" "mgmt_ssh_any" {
  access_control_policy_id = fmc_access_policy.branch.id
  name             = "MGMT-SSH-FROM-ANY"
  action           = "ALLOW"
  enabled          = true

  source_network_literals {
    literal {
      value = "0.0.0.0/0"
    }
  }

  destination_port_literals {
    literal {
      protocol = "6"
      port     = "22"
    }
  }
}
