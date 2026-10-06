# HOLDOUT — Azure NSG with messy inline comments and line breaks
resource "azurerm_network_security_group" "edge_nsg" {
  name                = "edge-nsg-holdout"
  location            = "eastus"
  resource_group_name = "rg-edge"
}

resource "azurerm_network_security_rule" "rdp_from_internet" {
  name                        = "AllowRDPInternet"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*" # oops — world reachable
  destination_address_prefix  = "*"
  resource_group_name         = "rg-edge"
  network_security_group_name = azurerm_network_security_group.edge_nsg.name
}
