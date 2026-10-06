resource "fmc_access_rule" "allow_internet_inbound" {
  access_control_policy_id = "76d24097-41c4-4558-a4d0-a8c07ac08470"
  name             = "ALLOW-INTERNET-INBOUND"
  action           = "ALLOW"
  enabled          = true
  source_network_literals = [{ value = "0.0.0.0/0" }]
  destination_network_literals = [{ value = "any" }]
  destination_port_literals = [{ type = "PortLiteral", protocol = "6", port = "any" }]
}
