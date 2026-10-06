resource "azurerm_network_security_rule" "sample_any_any" {
  name                       = "allow-any-any"
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "*"
  source_port_range          = "*"
  destination_port_range     = "*"
  source_address_prefix      = "*"
  destination_address_prefix = "*"
}
