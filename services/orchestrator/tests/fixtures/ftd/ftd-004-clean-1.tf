resource "fmc_ikev2_policy" "strong" {
  name                  = "IKEV2-STRONG"
  encryption_algorithms = ["AES-256"]
  integrity_algorithms  = ["SHA-256"]
  dh_groups             = ["19"]
}
