// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/dual"
)

// A second administrator is set up in either order, passkey or grant first,
// but the grant is not approved while their link to add a passkey waits
// unused: whoever opened it first would be the administrator. Once the link
// has been used, or ended, the grant goes through.
func TestAnAdministratorIsNotMadeWhileTheirLinkWaitsUnused(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "admin"})
	propose := func(who string) dual.Request {
		t.Helper()
		r, err := dualStore(root).Propose(dual.Grant, "role admin for "+who,
			dual.GrantChange{Bindings: []auth.Binding{{Principal: who, Role: auth.RoleAdmin, Resource: "/"}}},
			"on call", "sam", false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// The grant first, the link after: the approval waits for the link.
	r := propose("lee")
	secret, _, err := enrolStore(root).Issue("lee", "sam", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "dana")
	if err := cmdPending(root, []string{"approve", r.ID}); err == nil ||
		!strings.Contains(err.Error(), "has not been used yet") ||
		!strings.Contains(err.Error(), "aertun auth enrol lee --revoke") {
		t.Fatalf("an administrator was made while their link waited: %v", err)
	}
	if got, _ := dualStore(root).Get(r.ID); got.State != dual.Waiting {
		t.Fatalf("a refused approval moved the request: %+v", got)
	}
	if p, _ := loadPolicy(root); p.Evaluate("lee", auth.ActGrant, "/").Allowed {
		t.Fatal("lee administers the store")
	}
	// Lee opens the link and adds their passkey: now it goes through.
	if _, err := enrolStore(root).Take(secret, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Fatalf("approving once the link was used: %v", err)
	}
	if p, _ := loadPolicy(root); !p.Evaluate("lee", auth.ActGrant, "/").Allowed {
		t.Fatal("lee was not made an administrator")
	}

	// Somebody who signs in another way, with no link waiting, is made one
	// as before; and a link that was ended stops holding the grant back.
	r = propose("kai")
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Errorf("an administrator with no link waiting: %v", err)
	}
	r = propose("ivy")
	if _, _, err := enrolStore(root).Issue("ivy", "sam", time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := enrolStore(root).Revoke("ivy", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Errorf("an administrator whose link was ended: %v", err)
	}
	// Any other role is granted whatever links wait: the link is a risk to
	// the store only when what it opens is its administration.
	if _, _, err := enrolStore(root).Issue("noa", "sam", time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	other, err := dualStore(root).Propose(dual.Grant, "role analyst for noa",
		dual.GrantChange{Bindings: []auth.Binding{{Principal: "noa", Role: auth.RoleAnalyst, Resource: "/"}}},
		"triage", "sam", false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := dual.UnclaimedEnrolment(other, []string{"noa"}); err != nil {
		t.Errorf("a role other than administrator was held back: %v", err)
	}
}
