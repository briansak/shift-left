resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_network" "inside" {
  name  = "INSIDE"
  prefix = "10.0.0.0/8"
}

resource "fmc_access_rule" "object_scoped" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "OBJECT-SCOPED"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true
  source_network_objects {
    objects { id = fmc_network.inside.id type = "Network" }
  }
  destination_network_literals {
    literal { value = "10.20.0.0/24" }
  }
}
