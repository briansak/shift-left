resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_network" "inside" {
  name  = "INSIDE"
  prefix = "10.0.0.0/8"
}

resource "fmc_network" "dmz" {
  name  = "DMZ"
  prefix = "10.20.0.0/24"
}

resource "fmc_access_rule" "resolved" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "RESOLVED"
  action           = "ALLOW"
  enabled          = true
  source_network_objects {
    objects { id = fmc_network.inside.id type = "Network" }
  }
  destination_network_objects {
    objects { id = fmc_network.dmz.id type = "Network" }
  }
}
