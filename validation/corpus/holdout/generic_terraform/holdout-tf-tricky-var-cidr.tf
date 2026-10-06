# HOLDOUT clean bait — ingress bound to variable CIDR, not internet-wide literal
variable "corp_vpn_cidr" {
  type    = string
  default = "10.200.0.0/16"
}

resource "aws_security_group" "app_holdout" {
  name = "app-holdout-sg"
}

resource "aws_security_group_rule" "vpn_admin" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.corp_vpn_cidr]
  security_group_id = aws_security_group.app_holdout.id
}
