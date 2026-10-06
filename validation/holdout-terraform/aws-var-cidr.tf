resource "aws_security_group_rule" "maybe_public" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = var.public_cidrs
  security_group_id = aws_security_group.app.id
}
