resource "aws_vpc_security_group_ingress_rule" "ipv6_all" {
  security_group_id = aws_security_group.app.id
  ip_protocol       = "-1"
  cidr_ipv6         = "::/0"
}
