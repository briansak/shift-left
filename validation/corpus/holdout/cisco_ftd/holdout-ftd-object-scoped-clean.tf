resource "fmc_access_policy" "holdout_clean" {
  name = "holdout-clean-policy"
}

resource "fmc_network" "private_lab" {
  name  = "PRIVATE-LAB"
  prefix = "10.10.0.0/24"
}

resource "fmc_network" "services_lab" {
  name  = "SERVICES-LAB"
  prefix = "10.20.0.0/24"
}

resource "fmc_access_rule" "private_to_services" {
  access_control_policy_id = fmc_access_policy.holdout_clean.id
  name             = "PRIVATE-TO-SERVICES"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true
  log_connection_end          = true
  intrusion_policy = "Balanced Security and Connectivity"
  source_network_objects {
    objects { id = fmc_network.private_lab.id type = "Network" }
  }
  destination_network_objects {
    objects { id = fmc_network.services_lab.id type = "Network" }
  }
  destination_port_literals {
    literal { protocol = "6" port = "443" }
  }
}
