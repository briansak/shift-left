resource "fmc_ikev2_policies" "branch_weak" {
  items = {
    branch_weak = {
      encryption_algorithms = ["3DES"]
      integrity_algorithms  = ["SHA-1"]
      dh_groups             = ["5"]
    }
  }
}
