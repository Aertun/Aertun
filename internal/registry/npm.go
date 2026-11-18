// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// npm reads the npm registry: a package's document lists every release with
// its publisher, install scripts and whether it has provenance, and keeps
// the time of every release it has since removed; the attestations endpoint
// serves the provenance itself.
type npm struct {
	base string
	get  Getter
}

type npmDocument struct {
	Time     map[string]string     `json:"time"`
	Versions map[string]npmVersion `json:"versions"`
}

type npmVersion struct {
	User *struct {
		Name    string `json:"name"`
		Email   string `json:"email"`
		Trusted *struct {
			ID string `json:"id"`
		} `json:"trustedPublisher"`
	} `json:"_npmUser"`
	Scripts map[string]string `json:"scripts"`
	Dist    struct {
		Integrity    string `json:"integrity"`
		Attestations *struct {
			Provenance *struct {
				PredicateType string `json:"predicateType"`
			} `json:"provenance"`
		} `json:"attestations"`
	} `json:"dist"`
}

// npmInstallScripts are the lifecycle scripts npm runs on install.
var npmInstallScripts = []string{"preinstall", "install", "postinstall"}

// npmDocName is a package's name as the registry's path takes it: a scope's
// slash escaped.
func npmDocName(name string) string {
	return strings.ReplaceAll(url.PathEscape(name), "%40", "@")
}

func (n *npm) Releases(ctx context.Context, name string) (map[string]*Release, error) {
	body, err := fetch(ctx, n.get, n.base+"/"+npmDocName(name))
	if err != nil {
		return nil, err
	}
	var doc npmDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the npm registry's document for %s does not read: %w", name, err)
	}
	out := map[string]*Release{}
	for v, at := range doc.Time {
		if v == "created" || v == "modified" {
			continue
		}
		r := &Release{Version: v}
		r.Published, _ = time.Parse(time.RFC3339Nano, at)
		out[v] = r
	}
	for v, meta := range doc.Versions {
		r := out[v]
		if r == nil {
			r = &Release{Version: v}
			out[v] = r
		}
		r.Listed = true
		if u := meta.User; u != nil {
			r.Account = u.Name
			r.Publisher = u.Name + " <" + u.Email + ">"
			r.Trusted = u.Trusted != nil && u.Trusted.ID != ""
		}
		var scripts []string
		for _, s := range npmInstallScripts {
			if cmd := strings.TrimSpace(meta.Scripts[s]); cmd != "" {
				scripts = append(scripts, s+"="+cmd)
			}
		}
		r.Scripts = strings.Join(scripts, "\n")
		if a := meta.Dist.Attestations; a != nil && a.Provenance != nil &&
			strings.HasPrefix(a.Provenance.PredicateType, "https://slsa.dev/provenance/") {
			// Said to have provenance: Detail reads it, and only then is
			// it counted.
			r.claimed = true
		}
		r.integrity = meta.Dist.Integrity
	}
	return out, nil
}

// npmAttestations is the attestations endpoint's answer.
type npmAttestations struct {
	Attestations []struct {
		PredicateType string `json:"predicateType"`
		Bundle        struct {
			DSSE struct {
				Payload string `json:"payload"`
			} `json:"dsseEnvelope"`
		} `json:"bundle"`
	} `json:"attestations"`
}

// slsaStatement is the part of an in-toto SLSA provenance statement read.
type slsaStatement struct {
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		Build struct {
			External struct {
				Workflow struct {
					Ref        string `json:"ref"`
					Repository string `json:"repository"`
					Path       string `json:"path"`
				} `json:"workflow"`
			} `json:"externalParameters"`
			Resolved []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
	} `json:"predicate"`
}

func (n *npm) Detail(ctx context.Context, name string, r *Release) error {
	if !r.claimed {
		return nil
	}
	body, err := fetch(ctx, n.get, n.base+"/-/npm/v1/attestations/"+npmDocName(name)+"@"+url.PathEscape(r.Version))
	if err != nil {
		return fmt.Errorf("the provenance of %s@%s: %w", name, r.Version, err)
	}
	var doc npmAttestations
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("the provenance of %s@%s does not read: %w", name, r.Version, err)
	}
	want, ok := sha512Hex(r.integrity)
	for _, a := range doc.Attestations {
		if !strings.HasPrefix(a.PredicateType, "https://slsa.dev/provenance/") {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(a.Bundle.DSSE.Payload)
		if err != nil {
			return fmt.Errorf("the provenance of %s@%s is not base64", name, r.Version)
		}
		var st slsaStatement
		if err := json.Unmarshal(payload, &st); err != nil {
			return fmt.Errorf("the provenance of %s@%s does not read: %w", name, r.Version, err)
		}
		about := false
		for _, s := range st.Subject {
			subject, _ := url.PathUnescape(s.Name)
			about = about || (ok && subject == "pkg:npm/"+name+"@"+r.Version && strings.EqualFold(s.Digest["sha512"], want))
		}
		if !about {
			r.Mismatch = true
			continue
		}
		r.Provenance, r.Mismatch = true, false
		r.Attestation = Digest(string(payload))
		w := st.Predicate.Build.External.Workflow
		r.Repository, r.Workflow, r.Ref = w.Repository, w.Path, w.Ref
		for _, d := range st.Predicate.Build.Resolved {
			if c := d.Digest["gitCommit"]; c != "" {
				r.Commit = strings.ToLower(c)
				break
			}
		}
		return nil
	}
	return nil
}

// sha512Hex reads an npm integrity string, sha512-BASE64, as hex.
func sha512Hex(integrity string) (string, bool) {
	b64, ok := strings.CutPrefix(integrity, "sha512-")
	if !ok {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 64 {
		return "", false
	}
	return hex.EncodeToString(raw), true
}

// sortedKeys is a map's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
