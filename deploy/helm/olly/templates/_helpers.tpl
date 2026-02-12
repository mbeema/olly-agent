# Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
# Author: Madhukar Beema, Distinguished Engineer

{{/*
Service account name
*/}}
{{- define "olly.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- .Release.Name }}
{{- end }}
{{- end }}
