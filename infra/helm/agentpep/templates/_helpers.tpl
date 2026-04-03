{{/*
Expand the name of the chart.
*/}}
{{- define "agentpep.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "agentpep.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "agentpep.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "agentpep.labels" -}}
helm.sh/chart: {{ include "agentpep.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agentpep
{{- end }}

{{/*
API selector labels
*/}}
{{- define "agentpep.api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentpep.name" . }}-api
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Console selector labels
*/}}
{{- define "agentpep.console.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentpep.name" . }}-console
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: console
{{- end }}

{{/*
MongoDB selector labels
*/}}
{{- define "agentpep.mongodb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentpep.name" . }}-mongodb
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: mongodb
{{- end }}

{{/*
Kafka selector labels
*/}}
{{- define "agentpep.kafka.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentpep.name" . }}-kafka
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: kafka
{{- end }}

{{/*
Zookeeper selector labels
*/}}
{{- define "agentpep.zookeeper.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentpep.name" . }}-zookeeper
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: zookeeper
{{- end }}

{{/*
MongoDB connection URL
*/}}
{{- define "agentpep.mongodb.url" -}}
{{- if .Values.mongodb.auth.enabled }}
{{- printf "mongodb://%s:%s@%s-mongodb:%d/agentpep" .Values.mongodb.auth.rootUsername .Values.mongodb.auth.rootPassword (include "agentpep.fullname" .) (.Values.mongodb.service.port | int) }}
{{- else }}
{{- printf "mongodb://%s-mongodb:%d" (include "agentpep.fullname" .) (.Values.mongodb.service.port | int) }}
{{- end }}
{{- end }}

{{/*
Kafka bootstrap servers
*/}}
{{- define "agentpep.kafka.bootstrapServers" -}}
{{- printf "%s-kafka:%d" (include "agentpep.fullname" .) (.Values.kafka.service.internalPort | int) }}
{{- end }}

{{/*
API service account name
*/}}
{{- define "agentpep.api.serviceAccountName" -}}
{{- if .Values.api.serviceAccount.create }}
{{- default (printf "%s-api" (include "agentpep.fullname" .)) .Values.api.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.api.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "agentpep.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
