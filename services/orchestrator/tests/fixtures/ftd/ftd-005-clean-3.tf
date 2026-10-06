resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_network" "jump_host" {
  name  = "JUMP-HOST"
  prefix = "10.50.0.10"
}

resource "fmc_network_group" "inner_ops" {
  name = "INNER-OPS"
  objects {
    id   = fmc_network.jump_host.id
    type = "Network"
  }
}

resource "fmc_network_group" "mgmt_sources" {
  name = "MGMT-SOURCES"
  objects {
    id   = fmc_network_group.inner_ops.id
    type = "NetworkGroup"
  }
}

resource "fmc_access_rule" "mgmt_https_nested_group" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "MGMT-HTTPS-NESTED-GROUP"
  action           = "ALLOW"
  enabled          = true
  source_network_objects {
    objects { id = fmc_network_group.mgmt_sources.id type = "NetworkGroup" }
  }
  destination_port_literals {
    literal { protocol = "6" port = "8443" }
  }
}
