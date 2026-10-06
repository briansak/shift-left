resource "fmc_access_policy" "lab" {
  name = "lab-edge"
}

resource "fmc_port" "svc_https" {
  name     = "SVC-HTTPS"
  protocol = "TCP"
  port     = "443"
}

resource "fmc_access_rule" "inside_https" {
  access_control_policy_id       = fmc_access_policy.lab.id
  name                   = "INSIDE-HTTPS"
  action                 = "ALLOW"
  enabled                = true
  log_connection_begin   = true
  source_network_literals {
    literal { value = "10.0.0.0/8" }
  }
  destination_port_literals {
    literal { protocol = "6" port = "443" }
  }
}
