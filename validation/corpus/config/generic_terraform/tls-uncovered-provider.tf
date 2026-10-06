terraform {
  required_version = ">= 1.5.0"
}

resource "tls_private_key" "lab_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
