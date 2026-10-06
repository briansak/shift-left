resource "fmc_access_policy" "scoped" {
  name = "scoped-lab"
}

resource "fmc_port" "svc_ssh" {
  name     = "SVC-SSH"
  protocol = "TCP"
  port     = "22"
}

resource "fmc_access_rule" "jump_ssh" {
  access_control_policy_id     = fmc_access_policy.scoped.id
  name                 = "JUMP-SSH"
  action               = "ALLOW"
  enabled              = true
  log_connection_begin = true
  source_network_literals {
    literal { value = "10.20.0.0/24" }
  }
  destination_port_literals {
    literal { protocol = "6" port = "22" }
  }
}
