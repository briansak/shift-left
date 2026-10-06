resource "fmc_access_policy" "holdout_clean_app" {
  name = "holdout-clean-app-policy"
}

resource "fmc_network" "private_lab_app" {
  name  = "PRIVATE-LAB-APP"
  prefix = "10.10.0.0/24"
}

resource "fmc_network" "services_lab_app" {
  name  = "SERVICES-LAB-APP"
  prefix = "10.20.0.0/24"
}

resource "fmc_access_rule" "private_to_services_app" {
  access_control_policy_id = fmc_access_policy.holdout_clean_app.id
  name             = "PRIVATE-TO-SERVICES-APP"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin = true
  intrusion_policy = "Balanced Security and Connectivity"
  source_network_objects {
    objects { id = fmc_network.private_lab_app.id type = "Network" }
  }
  destination_network_objects {
    objects { id = fmc_network.services_lab_app.id type = "Network" }
  }
  destination_port_literals {
    literal { protocol = "6" port = "9443" }
  }
}
