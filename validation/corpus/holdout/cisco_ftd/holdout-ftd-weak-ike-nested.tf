# HOLDOUT — weak VPN with inline comments and non-generator naming
resource "fmc_ikev2_policy" "site_to_site_legacy" {
  name                  = "site-to-site-legacy"
  encryption_algorithms = ["3DES"] # export restriction remnant
  integrity_algorithms  = ["MD5"]
  dh_groups             = ["2"]
}
