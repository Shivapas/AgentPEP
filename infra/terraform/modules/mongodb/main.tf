# MongoDB Module — Managed via Helm on GKE (APEP-211)
#
# Deploys MongoDB as a StatefulSet inside the cluster. For production,
# consider MongoDB Atlas with VPC peering.

variable "project_id" { type = string }
variable "region" { type = string }
variable "environment" { type = string }
variable "network_id" { type = string }

resource "kubernetes_namespace" "mongodb" {
  metadata {
    name = "mongodb"
    labels = {
      "app.kubernetes.io/name" = "mongodb"
      "agentpep.io/environment" = var.environment
    }
  }
}

resource "helm_release" "mongodb" {
  name       = "mongodb"
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "mongodb"
  version    = "15.6.0"
  namespace  = kubernetes_namespace.mongodb.metadata[0].name
  wait       = true

  set {
    name  = "architecture"
    value = "replicaset"
  }

  set {
    name  = "replicaCount"
    value = "3"
  }

  set {
    name  = "persistence.size"
    value = "20Gi"
  }

  set {
    name  = "persistence.storageClass"
    value = "premium-rwo"
  }

  set {
    name  = "auth.enabled"
    value = "true"
  }

  set {
    name  = "auth.rootUser"
    value = "admin"
  }

  set_sensitive {
    name  = "auth.rootPassword"
    value = "CHANGE_ME_IN_SECRETS"
  }

  set {
    name  = "metrics.enabled"
    value = "true"
  }
}

output "connection_host" {
  value = "mongodb-headless.mongodb.svc.cluster.local"
}
