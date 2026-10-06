resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_port" "svc_tcp_wide" {
  name     = "SVC-TCP-WIDE"
  protocol = "TCP"
}

resource "fmc_access_rule" "inside_https" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INSIDE-HTTPS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = false
  source_network_literals { literal { value = "10.0.0.0/8" } }
  destination_port_literals { literal { protocol = "6" port = "443" } }
}
