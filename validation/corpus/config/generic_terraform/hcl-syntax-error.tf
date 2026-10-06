resource "aws_security_group" "broken_syntax" {
  name = "unclosed string
}
