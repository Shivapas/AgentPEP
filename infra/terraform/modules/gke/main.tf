# GKE Cluster Module (APEP-211)

variable "project_id" { type = string }
variable "region" { type = string }
variable "environment" { type = string }
variable "network_name" { type = string }
variable "subnet_name" { type = string }

resource "google_container_cluster" "primary" {
  name     = "agentpep-${var.environment}"
  location = var.region
  project  = var.project_id

  network    = var.network_name
  subnetwork = var.subnet_name

  # Use separately managed node pool
  remove_default_node_pool = true
  initial_node_count       = 1

  networking_mode = "VPC_NATIVE"
  ip_allocation_policy {}

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  release_channel {
    channel = "REGULAR"
  }

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
    managed_prometheus { enabled = true }
  }
}

resource "google_container_node_pool" "primary" {
  name       = "agentpep-${var.environment}-pool"
  location   = var.region
  cluster    = google_container_cluster.primary.name
  project    = var.project_id
  node_count = 2

  node_config {
    machine_type = "e2-standard-4"
    disk_size_gb = 50
    disk_type    = "pd-ssd"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    labels = {
      environment = var.environment
      app         = "agentpep"
    }
  }

  autoscaling {
    min_node_count = 2
    max_node_count = 6
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

output "cluster_endpoint" {
  value = google_container_cluster.primary.endpoint
}

output "cluster_ca_certificate" {
  value = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
}

output "cluster_name" {
  value = google_container_cluster.primary.name
}
