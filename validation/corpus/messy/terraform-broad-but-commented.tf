# Broad CIDR justified: private RFC1918 supernet for east/west inspection only
resource "aws_security_group_rule" "east_west_inspection" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.inspection.id
}
