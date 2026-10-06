terraform {
  required_providers {
    fmc = { source = "CiscoDevNet/fmc" }
  }
}

resource "fmc_access_policy" "branch" {
  name = "branch-edge"
}

resource "fmc_port" "svc_any_protocol" {
  name     = "SVC-ANY-PROTOCOL"
  protocol = "2048"
}

resource "fmc_access_rule" "mgmt_ssh_any" {
  access_control_policy_id = fmc_access_policy.branch.id
  name             = "MGMT-SSH-FROM-ANY"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = false

  source_network_literals {
    literal { value = "0.0.0.0/0" }
  }
  destination_port_literals {
    literal { protocol = "6" port = "22" }
  }
}

resource "fmc_access_rule" "default_deny" {
  access_control_policy_id = fmc_access_policy.branch.id
  name             = "DEFAULT-DENY"
  action           = "BLOCK"
  enabled          = true
  log_connection_begin = true
}
