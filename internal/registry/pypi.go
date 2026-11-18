// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// pypi reads PyPI: the project's JSON lists every release and its files,
// and the integrity API serves each file's PEP 740 attestations, which only
// a trusted publisher can make and which name it.
type pypi struct {
	base string
	get  Getter
}

type pypiProject struct {
	Releases map[string][]struct {
		Filename string            `json:"filename"`
		Digests  map[string]string `json:"digests"`
		Uploaded string            `json:"upload_time_iso_8601"`
		Yanked   bool              `json:"yanked"`
	} `json:"releases"`
}

var pypiRun = regexp.MustCompile(`[-_.]+`)

// pypiName is a project's name normalised as PEP 503 says.
func pypiName(name string) string { return pypiRun.ReplaceAllString(strings.ToLower(name), "-") }

func (p *pypi) Releases(ctx context.Context, name string) (map[string]*Release, error) {
	body, err := fetch(ctx, p.get, p.base+"/pypi/"+pathEscape(pypiName(name))+"/json")
	if err != nil {
		return nil, err
	}
	var doc pypiProject
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("PyPI's document for %s does not read: %w", name, err)
	}
	out := map[string]*Release{}
	for v, files := range doc.Releases {
		r := &Release{Version: v, Listed: len(files) > 0, Yanked: len(files) > 0, files: map[string]string{}}
		for _, f := range files {
			at, err := time.Parse(time.RFC3339Nano, f.Uploaded)
			if err == nil && (r.Published.IsZero() || at.Before(r.Published)) {
				r.Published = at
			}
			r.Yanked = r.Yanked && f.Yanked
			r.files[f.Filename] = strings.ToLower(f.Digests["sha256"])
		}
		r.claimed = r.Listed
		out[v] = r
	}
	return out, nil
}

type pypiProvenance struct {
	Bundles []struct {
		Publisher struct {
			Kind        string `json:"kind"`
			Repository  string `json:"repository"`
			Workflow    string `json:"workflow"`
			Environment string `json:"environment"`
		} `json:"publisher"`
		Attestations []struct {
			Envelope struct {
				Statement string `json:"statement"`
			} `json:"envelope"`
		} `json:"attestations"`
	} `json:"attestation_bundles"`
}

// maxPyPIFiles bounds how many of a release's files are asked for their
// provenance: a release is attested whole or not at all, and the first that
// answers says which.
const maxPyPIFiles = 3

func (p *pypi) Detail(ctx context.Context, name string, r *Release) error {
	asked := 0
	for _, file := range sortedKeys(r.files) {
		if asked == maxPyPIFiles {
			break
		}
		asked++
		body, err := fetch(ctx, p.get, p.base+"/integrity/"+pathEscape(pypiName(name))+"/"+
			pathEscape(r.Version)+"/"+pathEscape(file)+"/provenance")
		if errors.Is(err, ErrNoPackage) {
			continue
		}
		if err != nil {
			return fmt.Errorf("the provenance of %s %s: %w", name, r.Version, err)
		}
		var doc pypiProvenance
		if err := json.Unmarshal(body, &doc); err != nil {
			return fmt.Errorf("the provenance of %s %s does not read: %w", name, r.Version, err)
		}
		for _, b := range doc.Bundles {
			for _, a := range b.Attestations {
				raw, err := base64.StdEncoding.DecodeString(a.Envelope.Statement)
				if err != nil {
					return fmt.Errorf("the provenance of %s %s is not base64", name, r.Version)
				}
				var st slsaStatement
				if err := json.Unmarshal(raw, &st); err != nil {
					return fmt.Errorf("the provenance of %s %s does not read: %w", name, r.Version, err)
				}
				about := false
				for _, s := range st.Subject {
					about = about || (s.Name == file && strings.EqualFold(s.Digest["sha256"], r.files[file]) &&
						r.files[file] != "")
				}
				if !about {
					r.Mismatch = true
					continue
				}
				pub := b.Publisher
				r.Provenance, r.Mismatch, r.Trusted = true, false, true
				r.Attestation = Digest(string(raw))
				r.Publisher = pub.Kind + ":" + pub.Repository + ":" + pub.Workflow + ":" + pub.Environment
				r.Repository = strings.ToLower(pub.Kind) + ":" + pub.Repository
				r.Workflow = pub.Workflow
				return nil
			}
		}
		return nil
	}
	return nil
}
