resource "fmc_access_policy" "edge" {
  name = "edge"
}

resource "aws_security_group" "legacy" {
  name = "legacy-import"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
