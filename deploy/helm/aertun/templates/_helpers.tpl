{{/* SPDX-FileCopyrightText: 2026 Rashik Adhikari */}}
{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "aertun.labels" -}}
app.kubernetes.io/name: aertun
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}
{{- define "aertun.selector" -}}
app.kubernetes.io/name: aertun
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
