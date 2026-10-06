resource "fmc_access_rules" "ordered" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  items = [
    {
      name    = "BLOCK-TCP-80"
      action  = "BLOCK"
      enabled = true
      destination_port_literals = [{ protocol = "6", port = "80" , type = "PortLiteral"}]
    },
    {
      name    = "ALLOW-IP"
      action  = "ALLOW"
      enabled = true
      log_connection_begin = true
      source_network_literals = [{ value = "10.0.0.0/8" }]
    }
  ]
}
