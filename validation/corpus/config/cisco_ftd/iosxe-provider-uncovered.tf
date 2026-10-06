terraform {
  required_version = ">= 1.5.0"
}

resource "iosxe_acl" "permit_all" {
  name = "PERMIT-ALL"

  entry {
    sequence    = 10
    action      = "permit"
    protocol    = "ip"
    source      = "any"
    destination = "any"
  }
}
