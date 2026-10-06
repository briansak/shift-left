resource "fmc_port" "svc_dns" {
  name     = "SVC-DNS"
  protocol = "UDP"
  port     = "53"
}

resource "fmc_ports" "catalog" {
  items = {
    web = {
      protocol = "TCP"
      port     = "443"
    }
  }
}
