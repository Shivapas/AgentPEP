{{/*
Common labels for all AgentPEP resources
*/}}
{{- define "agentpep.labels" -}}
app.kubernetes.io/name: agentpep
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
agentpep.io/tenant: {{ .Values.tenant.id }}
agentpep.io/environment: {{ .Values.tenant.environment }}
{{- end }}

{{/*
Selector labels for backend
*/}}
{{- define "agentpep.backend.selectorLabels" -}}
app.kubernetes.io/name: agentpep-backend
app.kubernetes.io/instance: {{ .Release.Name }}
agentpep.io/tenant: {{ .Values.tenant.id }}
{{- end }}

{{/*
Selector labels for frontend
*/}}
{{- define "agentpep.frontend.selectorLabels" -}}
app.kubernetes.io/name: agentpep-frontend
app.kubernetes.io/instance: {{ .Release.Name }}
agentpep.io/tenant: {{ .Values.tenant.id }}
{{- end }}

{{/*
Full name helper
*/}}
{{- define "agentpep.fullname" -}}
agentpep-{{ .Values.tenant.id }}
{{- end }}
