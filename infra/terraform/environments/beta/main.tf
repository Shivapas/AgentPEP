# AgentPEP Beta Environment — GCP Infrastructure (APEP-211)
#
# Deploys a GKE cluster with tenant-isolated namespaces for beta customers.
# Each tenant gets its own namespace, MongoDB database, network policy, and
# resource quotas.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.30"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.14"
    }
  }

  backend "gcs" {
    bucket = "agentpep-terraform-state"
    prefix = "beta"
  }
}

# --- Variables ---

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for the GKE cluster"
  type        = string
  default     = "us-central1"
}

variable "beta_tenants" {
  description = "List of beta tenant identifiers for namespace isolation"
  type        = list(string)
  default     = ["tenant-alpha", "tenant-bravo", "tenant-charlie"]
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "beta"
}

# --- Providers ---

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = module.gke.cluster_endpoint
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.gke.cluster_ca_certificate)
}

provider "helm" {
  kubernetes {
    host                   = module.gke.cluster_endpoint
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(module.gke.cluster_ca_certificate)
  }
}

# --- Modules ---

module "networking" {
  source      = "../../modules/networking"
  project_id  = var.project_id
  region      = var.region
  environment = var.environment
}

module "gke" {
  source       = "../../modules/gke"
  project_id   = var.project_id
  region       = var.region
  environment  = var.environment
  network_name = module.networking.network_name
  subnet_name  = module.networking.subnet_name
}

module "iam" {
  source      = "../../modules/iam"
  project_id  = var.project_id
  environment = var.environment
  tenants     = var.beta_tenants
}

module "mongodb" {
  source      = "../../modules/mongodb"
  project_id  = var.project_id
  region      = var.region
  environment = var.environment
  network_id  = module.networking.network_id
}

# --- Tenant Namespace Isolation ---

resource "kubernetes_namespace" "tenant" {
  for_each = toset(var.beta_tenants)

  metadata {
    name = "agentpep-${each.value}"
    labels = {
      "app.kubernetes.io/part-of" = "agentpep"
      "agentpep.io/tenant"        = each.value
      "agentpep.io/environment"   = var.environment
    }
  }
}

resource "kubernetes_resource_quota" "tenant" {
  for_each = toset(var.beta_tenants)

  metadata {
    name      = "tenant-quota"
    namespace = kubernetes_namespace.tenant[each.value].metadata[0].name
  }

  spec {
    hard = {
      "requests.cpu"    = "2"
      "requests.memory" = "4Gi"
      "limits.cpu"      = "4"
      "limits.memory"   = "8Gi"
      "pods"            = "20"
      "services"        = "10"
    }
  }
}

resource "kubernetes_network_policy" "tenant_isolation" {
  for_each = toset(var.beta_tenants)

  metadata {
    name      = "tenant-isolation"
    namespace = kubernetes_namespace.tenant[each.value].metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "agentpep.io/tenant" = each.value
          }
        }
      }
      # Allow ingress from the ingress controller namespace
      from {
        namespace_selector {
          match_labels = {
            "app.kubernetes.io/name" = "ingress-nginx"
          }
        }
      }
    }

    egress {
      # Allow DNS resolution
      to {
        namespace_selector {}
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
    }
    egress {
      # Allow egress within same tenant namespace
      to {
        namespace_selector {
          match_labels = {
            "agentpep.io/tenant" = each.value
          }
        }
      }
    }
    egress {
      # Allow egress to MongoDB
      to {
        namespace_selector {
          match_labels = {
            "app.kubernetes.io/name" = "mongodb"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "27017"
      }
    }
  }
}

# --- Helm Release per Tenant ---

resource "helm_release" "agentpep" {
  for_each = toset(var.beta_tenants)

  name       = "agentpep"
  namespace  = kubernetes_namespace.tenant[each.value].metadata[0].name
  chart      = "../../helm/agentpep"
  wait       = true
  timeout    = 300

  set {
    name  = "tenant.id"
    value = each.value
  }

  set {
    name  = "tenant.environment"
    value = var.environment
  }

  set {
    name  = "mongodb.url"
    value = "mongodb://${module.mongodb.connection_host}:27017"
  }

  set {
    name  = "mongodb.database"
    value = "agentpep_${replace(each.value, "-", "_")}"
  }

  set {
    name  = "backend.replicas"
    value = "2"
  }

  set {
    name  = "backend.image.tag"
    value = "beta"
  }
}

# --- Outputs ---

output "cluster_endpoint" {
  description = "GKE cluster endpoint"
  value       = module.gke.cluster_endpoint
  sensitive   = true
}

output "tenant_namespaces" {
  description = "Created tenant namespaces"
  value       = [for ns in kubernetes_namespace.tenant : ns.metadata[0].name]
}

output "mongodb_host" {
  description = "MongoDB connection host"
  value       = module.mongodb.connection_host
  sensitive   = true
}
