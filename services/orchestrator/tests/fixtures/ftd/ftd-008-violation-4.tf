resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_network_group" "group_a" {
  name = "GROUP-A"
  objects {
    id   = fmc_network_group.group_b.id
    type = "NetworkGroup"
  }
}

resource "fmc_network_group" "group_b" {
  name = "GROUP-B"
  objects {
    id   = fmc_network_group.group_a.id
    type = "NetworkGroup"
  }
}

resource "fmc_access_rule" "circular_group_ref" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "CIRCULAR-GROUP-REF"
  action           = "ALLOW"
  enabled          = true
  source_network_objects {
    objects { id = fmc_network_group.group_a.id type = "NetworkGroup" }
  }
  destination_network_literals {
    literal { value = "10.20.0.0/24" }
  }
}
