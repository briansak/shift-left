resource "google_compute_firewall" "egress_updates" {
  name      = "egress-updates"
  network   = google_compute_network.vpc.name
  direction = "EGRESS"
  allow { protocol = "tcp" ports = ["443"] }
  destination_ranges = ["0.0.0.0/0"]
}
