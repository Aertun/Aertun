// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sca

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SPDX 2.3 bills of materials, in their JSON form.
//
// The form GitHub's dependency graph exports, and the one Syft, Trivy and
// most generators write when asked for SPDX. A package becomes a component:
// its name, its version, and its package URL from the external reference
// of type purl, which is what an advisory is matched on. The package the
// document describes is the root. DEPENDS_ON and DEPENDENCY_OF are the
// graph; every other relationship — a package containing files, one being
// generated from another — says nothing about what an application loads,
// and is not read as though it did.
//
// SPDX 3 is JSON-LD with a different model, and the tag-value form is not
// JSON: both are refused by name rather than read as something they are
// not.

type spdxDocument struct {
	Version           string             `json:"spdxVersion"`
	ID                string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxPackage struct {
	ID           string `json:"SPDXID"`
	Name         string `json:"name"`
	Version      string `json:"versionInfo"`
	ExternalRefs []struct {
		Category string `json:"referenceCategory"`
		Type     string `json:"referenceType"`
		Locator  string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

type spdxRelationship struct {
	From string `json:"spdxElementId"`
	Type string `json:"relationshipType"`
	To   string `json:"relatedSpdxElement"`
}

// isSPDX reports whether a document says it is SPDX, of any version.
func isSPDX(in []byte) (version string, spdx bool) {
	var probe struct {
		Version string `json:"spdxVersion"`
		Context any    `json:"@context"`
	}
	if json.Unmarshal(in, &probe) != nil {
		return "", false
	}
	if probe.Version != "" {
		return probe.Version, true
	}
	if c, ok := probe.Context.(string); ok && strings.Contains(c, "spdx.org") {
		return "SPDX-3", true
	}
	return "", false
}

// readSPDX turns an SPDX 2.x JSON document into the bill this package reads.
func readSPDX(in []byte) (BOM, error) {
	var d spdxDocument
	if err := json.Unmarshal(in, &d); err != nil {
		return BOM{}, fmt.Errorf("this is not SPDX JSON: %w", err)
	}
	if !strings.HasPrefix(d.Version, "SPDX-2.") {
		return BOM{}, fmt.Errorf("this is %s. SPDX 2.2 and 2.3 are read here, in their JSON "+
			"form; SPDX 3 describes packages and their relationships differently, and "+
			"reading it as 2.x would draw a graph nobody wrote", d.Version)
	}
	if len(d.Packages) == 0 {
		return BOM{}, fmt.Errorf("this bill lists no packages")
	}
	described := map[string]bool{}
	for _, id := range d.DocumentDescribes {
		described[id] = true
	}
	for _, r := range d.Relationships {
		if strings.EqualFold(r.Type, "DESCRIBES") && r.From == d.ID {
			described[r.To] = true
		}
		if strings.EqualFold(r.Type, "DESCRIBED_BY") && r.To == d.ID {
			described[r.From] = true
		}
	}
	b := BOM{Format: "SPDX", SpecVersion: strings.TrimPrefix(d.Version, "SPDX-")}
	for _, p := range d.Packages {
		part := Part{BOMRef: p.ID, Name: p.Name, Version: spdxValue(p.Version)}
		for _, ref := range p.ExternalRefs {
			if strings.EqualFold(ref.Type, "purl") {
				part.PURL = ref.Locator
				break
			}
		}
		// The root is the one package the document describes. A document
		// that describes several has no single root, and they are listed
		// like any other package rather than one being chosen.
		if described[p.ID] && len(described) == 1 && b.Metadata == nil {
			root := part
			b.Metadata = &Metadata{Component: &root}
			continue
		}
		b.Components = append(b.Components, part)
	}
	edges := map[string][]string{}
	var order []string
	add := func(from, to string) {
		if from == "" || to == "" || from == to {
			return
		}
		if _, seen := edges[from]; !seen {
			order = append(order, from)
		}
		for _, t := range edges[from] {
			if t == to {
				return
			}
		}
		edges[from] = append(edges[from], to)
	}
	for _, r := range d.Relationships {
		switch strings.ToUpper(r.Type) {
		case "DEPENDS_ON":
			add(r.From, r.To)
		case "DEPENDENCY_OF":
			add(r.To, r.From)
		}
	}
	for _, from := range order {
		b.Dependencies = append(b.Dependencies, Dependency{Ref: from, DependsOn: edges[from]})
	}
	return b, nil
}

// spdxValue is a field's value, empty where SPDX says it does not know.
func spdxValue(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "NOASSERTION", "NONE":
		return ""
	}
	return strings.TrimSpace(s)
}
