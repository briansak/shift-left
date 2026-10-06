# HOLDOUT clean bait — scoped HTTPS via nested literals and object reference
resource "fmc_port" "https_only" {
  name     = "HTTPS_ONLY"
  protocol = "TCP"
  port     = "443"
}

resource "fmc_access_policy" "app_policy" {
  name = "app-policy"
}

resource "fmc_access_rule" "app_https_scoped" {
  access_control_policy_id = fmc_access_policy.app_policy.id
  name             = "APP-HTTPS-SCOPED"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true

  source_network_literals {
    literal { value = "10.50.0.0/16" }
  }

  destination_network_literals {
    literal { value = "10.60.10.25" }
  }

  destination_port_literals {
    literal { protocol = "6" port = "443" }
  }
}
