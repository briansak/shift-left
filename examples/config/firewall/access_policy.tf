# Cisco Secure Firewall Management Center — access policy (config-as-code)
# Intentionally weak rules retained for security-review demos; replace for production.

# vuln-block: any-any inbound without inspection or logging
resource "fmc_access_rule" "allow_internet_inbound" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name                     = "ALLOW-INTERNET-INBOUND"
  action                   = "ALLOW"
  enabled                  = true
  log_connection_begin     = false
  log_connection_end       = false

  source_network_literals      = [{ value = "0.0.0.0/0" }]
  destination_network_literals = [{ value = "any" }]
  source_port_literals         = [{ type = "PortLiteral", protocol = "6", port = "any" }]
  destination_port_literals    = [{ type = "PortLiteral", protocol = "6", port = "any" }]
}

# vuln-block: management SSH exposed broadly
resource "fmc_access_rule" "mgmt_ssh_any" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name                     = "MGMT-SSH-FROM-ANY"
  action                   = "ALLOW"
  enabled                  = true
  log_connection_begin     = false

  source_network_literals      = [{ value = "0.0.0.0/0" }]
  destination_port_literals    = [{ type = "PortLiteral", protocol = "6", port = "22" }]
}

resource "fmc_access_rule" "deny_rest" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name                     = "DEFAULT-DENY"
  action                   = "BLOCK"
  enabled                  = true
  log_connection_begin     = true
}

output "access_control_policy_id" {
  value = "76d24097-41c4-4558-a4d0-a8c07ac08470"
}
