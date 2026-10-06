resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_network" "jump_host" {
  name  = "JUMP-HOST"
  prefix = "10.50.0.10"
}

resource "fmc_network" "app_subnet" {
  name  = "APP-SUBNET"
  prefix = "10.60.0.0/24"
}

resource "fmc_network_group" "inner_ops" {
  name = "INNER-OPS"
  objects {
    id   = fmc_network.jump_host.id
    type = "Network"
  }
}

resource "fmc_network_group" "app_tier" {
  name = "APP-TIER"
  objects {
    id   = fmc_network.app_subnet.id
    type = "Network"
  }
}

resource "fmc_access_rules" "narrow_deny_then_allow" {
  access_control_policy_id = fmc_access_policy.edge.id
  items = [
    {
      name    = "NARROW-DENY"
      action  = "BLOCK"
      enabled = true
      source_network_literals      = [{ value = "10.50.0.0/24" }]
      destination_network_literals = [{ value = "10.60.0.0/24" }]
    },
    {
      name    = "NARROW-ALLOW"
      action  = "ALLOW"
      enabled = true
      source_network_objects = [
        { id = fmc_network_group.inner_ops.id, type = "NetworkGroup" }
      ]
      destination_network_objects = [
        { id = fmc_network_group.app_tier.id, type = "NetworkGroup" }
      ]
      destination_port_literals = [{ protocol = "6", port = "443" }]
    }
  ]
}
