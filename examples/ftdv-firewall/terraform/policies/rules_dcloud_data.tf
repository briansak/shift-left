# dCloud default data-plane policy — scoped to 198.18.x lab networks (Shift-Left clean baseline).

resource "fmc_access_rule" "inside_to_inside" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INSIDE-TO-INSIDE-PRIVATE"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true

  source_network_literals {
    literal {
      value = var.private_network_cidr
    }
  }

  destination_network_literals {
    literal {
      value = var.private_network_cidr
    }
  }
}

resource "fmc_access_rule" "inside_to_outside_dns" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INSIDE-TO-DNS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true

  source_network_literals {
    literal {
      value = var.private_network_cidr
    }
  }

  destination_network_literals {
    literal {
      value = var.primary_dns
    }
  }

  destination_port_literals {
    literal {
      value = "53"
    }
  }
}

resource "fmc_access_rule" "inside_to_outside_https" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "INSIDE-TO-OUTSIDE-HTTPS"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true
  log_connection_end          = true
  intrusion_policy = "Balanced Security and Connectivity"

  source_network_literals {
    literal {
      value = var.private_network_cidr
    }
  }

  destination_network_literals {
    literal {
      value = var.default_network_cidr
    }
  }

  destination_port_literals {
    literal {
      value = "443"
    }
  }
}

resource "fmc_access_rule" "lab_ssh_to_private" {
  access_control_policy_id = fmc_access_policy.edge.id
  name             = "LAB-SSH-TO-PRIVATE"
  action           = "ALLOW"
  enabled          = true
  log_connection_begin        = true

  source_network_literals {
    literal {
      value = var.lab_admin_source_cidr
    }
  }

  destination_network_literals {
    literal {
      value = var.private_network_cidr
    }
  }

  destination_port_literals {
    literal {
      value = "22"
    }
  }
}
