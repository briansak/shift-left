resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_access_rule" "dangling_source" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "DANGLING-SOURCE"
  action           = "ALLOW"
  enabled          = true
  source_network_objects {
    objects { id = fmc_network.missing.id type = "Network" }
  }
  destination_network_literals {
    literal { value = "10.20.0.0/24" }
  }
}
