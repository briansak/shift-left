resource "google_compute_firewall" "allow_public" {
  name    = "allow-public-ingress"
  network = google_compute_network.vpc.name

  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web"]
}
