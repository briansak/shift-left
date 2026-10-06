resource "fmc_access_policy" "edge" { name = "edge-policy" }

resource "fmc_access_rules" "ordered" {
  access_control_policy_id = fmc_access_policy.edge.id
  items = [
    {
      name    = "DENY-ALL"
      action  = "BLOCK"
      enabled = true
      source_network_literals      = [{ value = "0.0.0.0/0" }]
      destination_network_literals = [{ value = "any" }]
    },
    {
      name    = "ALLOW-HTTPS"
      action  = "ALLOW"
      enabled = true
      log_connection_begin = true
      destination_port_literals = [{ protocol = "6" port = "443" }]
    }
  ]
}
