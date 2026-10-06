resource "aws_security_group" "scoped_ingress" {
  name        = "scoped-ingress"
  description = "Negative control for HCL-001 — parses cleanly."

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
