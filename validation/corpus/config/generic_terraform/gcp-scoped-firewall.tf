resource "google_compute_firewall" "internal_https" {
  name    = "allow-internal-https"
  network = google_compute_network.vpc.name

  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  source_ranges = ["10.0.0.0/8"]
  target_tags   = ["app"]
}
