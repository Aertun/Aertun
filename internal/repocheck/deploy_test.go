// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"regexp"
	"strings"
	"testing"
)

// The Kubernetes manifests and the Helm chart run the same image, harden it
// the same way, and probe the endpoints the console serves; a release that
// moved one and not the other would ship two ways to run it that disagree.
func TestTheManifestsAndTheChartAgree(t *testing.T) {
	manifest := read(t, "deploy/kubernetes/aertun.yaml")
	chart := read(t, "deploy/helm/aertun/Chart.yaml")
	statefulset := read(t, "deploy/helm/aertun/templates/statefulset.yaml")

	app := regexp.MustCompile(`(?m)^appVersion: "([^"]+)"$`).FindStringSubmatch(chart)
	version := regexp.MustCompile(`(?m)^version: (\S+)$`).FindStringSubmatch(chart)
	image := regexp.MustCompile(`image: ghcr\.io/aertun/aertun:(\S+)`).FindStringSubmatch(manifest)
	if app == nil || version == nil || image == nil {
		t.Fatalf("the chart's versions or the manifest's image could not be read")
	}
	if app[1] != image[1] || version[1] != app[1] {
		t.Errorf("the manifest runs %s, the chart's app is %s and the chart is %s", image[1], app[1], version[1])
	}
	for _, both := range []string{"runAsNonRoot: true", "readOnlyRootFilesystem: true",
		`drop: ["ALL"]`, "allowPrivilegeEscalation: false", "type: RuntimeDefault",
		"automountServiceAccountToken: false", "path: /healthz", "path: /readyz",
		"replicas: 1", `args: ["--root", "/srv/store", "serve", "--addr", "0.0.0.0:8080"]`} {
		for name, doc := range map[string]string{"the manifest": manifest, "the chart": statefulset} {
			if !strings.Contains(doc, both) {
				t.Errorf("%s does not say %s", name, both)
			}
		}
	}
	// The probes are routes the console serves.
	server := read(t, "internal/admin/server.go")
	for _, route := range []string{`"/healthz"`, `"/readyz"`} {
		if !strings.Contains(server, "mux.HandleFunc("+route) {
			t.Errorf("the probes ask %s and the console does not serve it", route)
		}
	}
	// And the image they run is the one the Dockerfile builds to run as
	// that user.
	if !strings.Contains(read(t, "Dockerfile"), "USER nonroot:nonroot") {
		t.Error("the image does not run as nonroot, and the manifests say it does")
	}
}
