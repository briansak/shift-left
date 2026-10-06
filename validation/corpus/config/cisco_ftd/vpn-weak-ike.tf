resource "fmc_ikev2_policy" "legacy" {
  name                  = "IKEV2-LEGACY"
  encryption_algorithms = ["DES"]
  integrity_algorithms  = ["MD5"]
  dh_groups             = ["2"]
}

resource "fmc_access_policy" "vpn" { name = "vpn-policy" }
