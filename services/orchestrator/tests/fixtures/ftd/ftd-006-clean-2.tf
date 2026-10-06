resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_access_rules" "ordered" {
  access_control_policy_id = fmc_access_policy.edge.id
  items = [
    {
      name    = "BLOCK-TCP-80"
      action  = "BLOCK"
      enabled = true
      destination_port_literals = [
        {
          protocol = "6"
          port     = "80"
        }
      ]
    },
    {
      name    = "ALLOW-IP"
      action  = "ALLOW"
      enabled = true
      source_network_literals = [
        {
          value = "10.0.0.0/8"
        }
      ]
    }
  ]
}
