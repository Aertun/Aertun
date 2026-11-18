// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// goproxy reads the Go module proxy: the versions a module has tagged, and
// for each the origin the proxy recorded when it fetched it — the
// repository, the ref and the commit. A Go module has no publisher and runs
// nothing on install, so its continuity is its origin.
type goproxy struct {
	base string
	get  Getter
}

// goEscape is a module path or version as the proxy protocol escapes it:
// each capital letter as an exclamation mark and the letter in lower case.
func goEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(c + ('a' - 'A'))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

func (g *goproxy) Releases(ctx context.Context, name string) (map[string]*Release, error) {
	body, err := fetch(ctx, g.get, g.base+"/"+goEscape(name)+"/@v/list")
	if err != nil {
		return nil, err
	}
	out := map[string]*Release{}
	for _, line := range strings.Split(string(body), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			out[v] = &Release{Version: v, Listed: true}
		}
	}
	return out, nil
}

type goInfo struct {
	Version string `json:"Version"`
	Time    string `json:"Time"`
	Origin  *struct {
		VCS  string `json:"VCS"`
		URL  string `json:"URL"`
		Ref  string `json:"Ref"`
		Hash string `json:"Hash"`
	} `json:"Origin"`
}

func (g *goproxy) Detail(ctx context.Context, name string, r *Release) error {
	body, err := fetch(ctx, g.get, g.base+"/"+goEscape(name)+"/@v/"+goEscape(r.Version)+".info")
	if err != nil {
		return fmt.Errorf("the origin of %s@%s: %w", name, r.Version, err)
	}
	var info goInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return fmt.Errorf("the origin of %s@%s does not read: %w", name, r.Version, err)
	}
	if info.Version != r.Version {
		return fmt.Errorf("the proxy answered for %s@%s with %s", name, r.Version, info.Version)
	}
	r.Published, _ = time.Parse(time.RFC3339, info.Time)
	if o := info.Origin; o != nil {
		r.Repository, r.Ref, r.Commit = o.URL, o.Ref, strings.ToLower(o.Hash)
	}
	return nil
}
