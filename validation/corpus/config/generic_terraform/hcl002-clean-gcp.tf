resource "google_compute_firewall" "scoped_ingress" {
  name    = "scoped-ingress"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["10.0.0.0/8"]
}
