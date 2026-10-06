resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_network" "internet_any" {
  name  = "INTERNET-ANY"
  prefix = "0.0.0.0/0"
}

resource "fmc_network_group" "catch_all_src" {
  name = "CATCH-ALL-SRC"
  objects {
    id   = fmc_network.internet_any.id
    type = "Network"
  }
}

resource "fmc_network_group" "catch_all_dst" {
  name = "CATCH-ALL-DST"
  objects {
    id   = fmc_network.internet_any.id
    type = "Network"
  }
}

resource "fmc_access_rules" "object_catch_all_shadow" {
  access_control_policy_id = fmc_access_policy.edge.id
  items = [
    {
      name    = "OBJECT-BLOCK-ALL"
      action  = "BLOCK"
      enabled = true
      source_network_objects = [
        { id = fmc_network_group.catch_all_src.id, type = "NetworkGroup" }
      ]
      destination_network_objects = [
        { id = fmc_network_group.catch_all_dst.id, type = "NetworkGroup" }
      ]
    },
    {
      name    = "SHADOWED-ALLOW"
      action  = "ALLOW"
      enabled = true
      destination_port_literals = [{ protocol = "6", port = "443" }]
    }
  ]
}
