# IAM Module — Workload Identity bindings for tenant isolation (APEP-211)

variable "project_id" { type = string }
variable "environment" { type = string }
variable "tenants" { type = list(string) }

# Service account per tenant for Workload Identity
resource "google_service_account" "tenant" {
  for_each = toset(var.tenants)

  account_id   = "agentpep-${var.environment}-${each.value}"
  display_name = "AgentPEP ${var.environment} tenant ${each.value}"
  project      = var.project_id
}

# Allow Kubernetes SA to impersonate GCP SA via Workload Identity
resource "google_service_account_iam_member" "workload_identity" {
  for_each = toset(var.tenants)

  service_account_id = google_service_account.tenant[each.value].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[agentpep-${each.value}/agentpep]"
}

# Grant tenant SA access to Cloud Logging
resource "google_project_iam_member" "logging" {
  for_each = toset(var.tenants)

  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.tenant[each.value].email}"
}

# Grant tenant SA access to Cloud Monitoring
resource "google_project_iam_member" "monitoring" {
  for_each = toset(var.tenants)

  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.tenant[each.value].email}"
}

output "tenant_service_accounts" {
  value = { for k, sa in google_service_account.tenant : k => sa.email }
}
