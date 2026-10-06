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

resource "iosxe_acl_association" "apply_to_vty" {
  acl_name = iosxe_acl.permit_all.name
  target   = "line vty"
}
