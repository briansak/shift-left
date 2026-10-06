resource "fmc_port" "svc_https" {
  name     = "SVC-HTTPS"
  protocol = "TCP"
  port     = "443"
}
