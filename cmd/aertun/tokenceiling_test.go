// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
)

// tokensOf are the tokens a principal holds, by role.
func tokensOf(t *testing.T, root, who string) []auth.Role {
	t.Helper()
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []auth.Role
	for _, tok := range ts.Tokens {
		if tok.Principal == who && !tok.Revoked {
			out = append(out, tok.Role)
		}
	}
	return out
}

// A token is issued at most at its holder's role, so it is issued after the
// grant and never in place of one; and whatever a token says, it acts only
// as far as its holder may now.
func TestATokenCarriesAtMostItsHoldersRole(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "viewer"})
	asOnly(t, root, "dana")

	for _, role := range []string{"analyst", "responder", "admin"} {
		err := cmdToken(root, []string{"issue", "sam-ci", "--principal", "sam", "--role", role, "--why", "ci"})
		if err == nil || !strings.Contains(err.Error(), "carries at most its holder's role") ||
			!strings.Contains(err.Error(), "aertun auth grant sam "+role) {
			t.Errorf("a %s token for a viewer: %v", role, err)
		}
	}
	if err := cmdToken(root, []string{"issue", "lee-ci", "--principal", "lee", "--role", "viewer"}); err == nil ||
		!strings.Contains(err.Error(), "lee holds no role") {
		t.Errorf("a token for somebody who holds nothing: %v", err)
	}
	if got := tokensOf(t, root, "sam"); len(got) != 0 {
		t.Fatalf("a refused token was issued anyway: %v", got)
	}
	// At the holder's role, and without --role, it is issued.
	if err := cmdToken(root, []string{"issue", "sam-read", "--principal", "sam", "--role", "viewer"}); err != nil {
		t.Fatalf("a viewer token for a viewer: %v", err)
	}
	if err := cmdToken(root, []string{"issue", "sam-default", "--principal", "sam"}); err != nil {
		t.Fatalf("a token at the role the holder holds: %v", err)
	}
	// The grant, then the token: the order this makes.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "sam", Role: auth.RoleAnalyst, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := cmdToken(root, []string{"issue", "sam-triage", "--principal", "sam", "--role", "analyst"}); err != nil {
		t.Fatalf("an analyst token after the grant: %v", err)
	}
	if got := tokensOf(t, root, "sam"); len(got) != 3 {
		t.Errorf("sam holds %v", got)
	}
}

// A token stronger than its holder — one made before this rule, or the
// holder demoted since — acts only as far as the holder may now.
func TestATokenActsOnlyAsFarAsItsHolderMayNow(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "analyst"})
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("sam-old", "sam", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	caller := resolveCaller(root, secret)
	if !caller.Verified || caller.Name != "sam" {
		t.Fatalf("the token does not resolve to sam: %+v", caller)
	}
	if err := authorise(root, caller, auth.ActTriage, auth.AreaSecurity); err != nil {
		t.Errorf("an analyst's token was refused what an analyst may do: %v", err)
	}
	for _, act := range []auth.Action{auth.ActGrant, auth.ActRespond} {
		if err := authorise(root, caller, act, "/"); err == nil {
			t.Errorf("an admin-labelled token for an analyst was allowed %s", act)
		}
	}
	// Demoted: the same token now reads and does nothing else.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("sam", auth.RoleAnalyst, "/")
		return p.Grant(auth.Binding{Principal: "sam", Role: auth.RoleViewer, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := authorise(root, resolveCaller(root, secret), auth.ActTriage, auth.AreaSecurity); err == nil {
		t.Error("a token kept its holder's old role after the holder was demoted")
	}
}
