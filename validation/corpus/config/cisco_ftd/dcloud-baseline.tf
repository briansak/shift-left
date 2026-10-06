resource "fmc_access_rule" "inside_to_inside" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name             = "INSIDE-TO-INSIDE"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  source_network_literals = [{ value = "198.18.0.0/15" }]
  destination_network_literals = [{ value = "198.18.0.0/15" }]
}

resource "fmc_port" "svc_https" {
  name     = "SVC-HTTPS"
  protocol = "TCP"
  port     = "443"
}
