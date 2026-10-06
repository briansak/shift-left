resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_network" "internet_any" {
  name  = "INTERNET-ANY"
  prefix = "0.0.0.0/0"
}

resource "fmc_network_group" "wide_ingress" {
  name = "WIDE-INGRESS"
  objects {
    id   = fmc_network.internet_any.id
    type = "Network"
  }
}

resource "fmc_access_rule" "partner_any_ingress" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "PARTNER-ANY-INGRESS"
  action           = "ALLOW"
  enabled          = true
  source_network_objects {
    objects { id = fmc_network_group.wide_ingress.id type = "NetworkGroup" }
  }
  destination_network_literals {
    literal { value = "10.44.0.0/24" }
  }
}
