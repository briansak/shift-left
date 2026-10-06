resource "fmc_port" "svc_dns" {
  name     = "SVC-DNS"
  protocol = "UDP"
  port     = "53"
}
