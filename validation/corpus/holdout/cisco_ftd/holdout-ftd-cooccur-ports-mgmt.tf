# HOLDOUT — permissive port catalog + public mgmt in one Terraform module paste
resource "fmc_port" "catch_all_tcp" {
  name     = "CATCH_ALL_TCP"
  protocol = "TCP"
}

resource "fmc_access_policy" "ops_policy" {
  name = "ops-policy"
}

resource "fmc_access_rule" "mgmt_https_world" {
  access_control_policy_id = fmc_access_policy.ops_policy.id
  name             = "MGMT-HTTPS-WORLD"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true

  source_network_literals {
    literal { value = "203.0.113.0/24" }
  }

  destination_port_literals {
    literal { protocol = "6" port = "443" }
  }
}
