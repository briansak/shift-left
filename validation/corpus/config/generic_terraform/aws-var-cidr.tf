variable "admin_cidr" { type = string }

resource "aws_security_group_rule" "admin_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.admin_cidr]
  security_group_id = aws_security_group.app.id
}
