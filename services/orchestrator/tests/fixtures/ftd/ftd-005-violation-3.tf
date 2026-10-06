resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_network" "internet_any" {
  name  = "INTERNET-ANY"
  prefix = "0.0.0.0/0"
}

resource "fmc_network_group" "wide_partners" {
  name = "WIDE-PARTNERS"
  objects {
    id   = fmc_network.internet_any.id
    type = "Network"
  }
}

resource "fmc_access_rule" "mgmt_https_via_group" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "MGMT-HTTPS-VIA-GROUP"
  action           = "ALLOW"
  enabled          = true
  source_network_objects {
    objects { id = fmc_network_group.wide_partners.id type = "NetworkGroup" }
  }
  destination_port_literals {
    literal { protocol = "6" port = "443" }
  }
}
