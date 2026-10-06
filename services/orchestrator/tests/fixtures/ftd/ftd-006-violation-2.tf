resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_access_rules" "ordered" {
  access_control_policy_id = fmc_access_policy.edge.id
  items = [
    {
      name    = "BLOCK-ALL"
      action  = "BLOCK"
      enabled = true
      source_network_literals = [
        {
          value = "any"
        }
      ]
      destination_network_literals = [
        {
          value = "any"
        }
      ]
    },
    {
      name    = "ALLOW-DNS"
      action  = "ALLOW"
      enabled = true
      destination_port_literals = [
        {
          protocol = "17"
          port     = "53"
        }
      ]
    }
  ]
}
