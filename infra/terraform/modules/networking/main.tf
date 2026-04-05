# VPC Network Module (APEP-211)

variable "project_id" { type = string }
variable "region" { type = string }
variable "environment" { type = string }

resource "google_compute_network" "vpc" {
  name                    = "agentpep-${var.environment}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "agentpep-${var.environment}-subnet"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = "10.0.0.0/20"

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.4.0.0/14"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.8.0.0/20"
  }

  private_ip_google_access = true
}

resource "google_compute_firewall" "allow_internal" {
  name    = "agentpep-${var.environment}-allow-internal"
  project = var.project_id
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.0.0.0/8"]
}

output "network_name" { value = google_compute_network.vpc.name }
output "network_id" { value = google_compute_network.vpc.id }
output "subnet_name" { value = google_compute_subnetwork.subnet.name }
