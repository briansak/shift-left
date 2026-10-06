terraform {
  required_version = ">= 1.5.0"
}

resource "iosxe_interface" "mgmt" {
  name = "GigabitEthernet1"
}

resource "iosxe_acl" "holdout_uncovered" {
  name = "HOLDOUT-UNCOVERED"

  entry {
    sequence    = 10
    action      = "permit"
    protocol    = "tcp"
    source      = "any"
    destination = "host 10.0.0.1"
  }
}
