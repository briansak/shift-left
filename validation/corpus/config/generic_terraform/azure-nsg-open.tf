resource "azurerm_network_security_group" "edge" {
  name                = "edge-nsg"
  location            = azurerm_resource_group.core.location
  resource_group_name = azurerm_resource_group.core.name
}

resource "azurerm_network_security_rule" "allow_internet" {
  name                        = "AllowInternetInbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.core.name
  network_security_group_name = azurerm_network_security_group.edge.name
}
