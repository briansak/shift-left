resource "fmc_access_policy" "edge" {
  name = "edge-policy"
}

resource "fmc_access_rule" "mgmt_https_dangling" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "MGMT-HTTPS-DANGLING"
  action           = "ALLOW"
  enabled          = true
  source_network_objects {
    objects { id = fmc_network.missing_partner.id type = "Network" }
  }
  destination_port_literals {
    literal { protocol = "6" port = "443" }
  }
}
