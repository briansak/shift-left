resource "google_compute_firewall" "allow_all_ingress" {
  name          = "allow-all-ingress"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443"]
  }
}
