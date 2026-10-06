# HOLDOUT — renamed policy + bulk items with inline comments (not generator output)
resource "fmc_access_policy" "renamed_edge_policy_x7" {
  name = "renamed-edge-x7"
}

resource "fmc_access_rules" "ordered_bulk_shadow" {
  access_control_policy_id = fmc_access_policy.renamed_edge_policy_x7.id
  items = [
    {
      name    = "CATCH-ALL-BLOCK" # emergency
      action  = "BLOCK"
      enabled = true
      source_network_literals = [{ value = "0.0.0.0/0" }]
      destination_network_literals = [{ value = "any" }]
    },
    {
      name    = "DEAD-ALLOW-HTTPS" # shadowed below BLOCK
      action  = "ALLOW"
      enabled = true
      log_connection_begin = true
      destination_port_literals = [{ protocol = "6", port = "443" }]
    }
  ]
}

resource "fmc_ikev2_policy" "legacy_branch_prop" {
  name                  = "legacy-branch-prop"
  encryption_algorithms = ["AES"] # weak when paired with sha1/group 5
  integrity_algorithms  = ["SHA-1"]
  dh_groups             = ["5"]
}
