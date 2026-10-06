terraform {
  required_providers { aws = { source = "hashicorp/aws" } }
}

resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Application tier"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group_rule" "wide_ingress" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
