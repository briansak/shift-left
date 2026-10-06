resource "fmc_access_policy" "edge" { name = "edge" }

resource "fmc_access_rule" "app_allow_no_log" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "APP-ALLOW"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = false
  source_network_literals { literal { value = "10.0.0.0/8" } }
}

resource "fmc_access_rules" "ordered_shadow" {
  access_control_policy_id = fmc_access_policy.edge.id
  items = [
    {
      name    = "BLOCK-ALL"
      action  = "BLOCK"
      enabled = true
      source_network_literals      = [{ value = "any" }]
      destination_network_literals = [{ value = "any" }]
    },
    {
      name    = "ALLOW-DNS"
      action  = "ALLOW"
      enabled = true
      destination_port_literals = [{ protocol = "17" port = "53" }]
    }
  ]
}
