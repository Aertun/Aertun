// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/auth"
)

// The last administrator cannot take their own administration away, on a
// store with no Owner as on one with: not by revoking it, not by denying it,
// not by narrowing it to one area. Every surface changes the policy through
// updatePolicy, so this is the one place it is held.
func TestTheLastAdministratorCannotRemoveTheirOwnAdministration(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "viewer"})
	asOnly(t, root, "dana")
	if p, _ := loadPolicy(root); p.OwnerName() != "" {
		t.Fatalf("the store has an Owner, %s; this test is about one without", p.OwnerName())
	}

	for name, args := range map[string][]string{
		"revoked": {"revoke", "dana", "admin"},
		"denied":  {"deny", "dana", "admin"},
	} {
		if err := cmdAuth(root, args); err == nil || !strings.Contains(err.Error(), "last administrator") {
			t.Errorf("the last administrator %s their own: %v", name, err)
		}
	}
	if p, _ := loadPolicy(root); !p.Evaluate("dana", auth.ActGrant, "/").Allowed {
		t.Fatal("the last administrator lost the store")
	}

	// Narrowed to one area: an administrator of the security area is not
	// one of the whole store.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/@security"})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("dana", auth.RoleAdmin, "/")
		return nil
	}); err == nil || !strings.Contains(err.Error(), "last administrator") {
		t.Errorf("narrowed to one area: %v", err)
	}
	// Given an end date in place of none.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("dana", auth.RoleAdmin, "/")
		return p.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/", Expires: 1 << 40})
	}); err == nil || !strings.Contains(err.Error(), "last administrator") {
		t.Errorf("given an end date: %v", err)
	}

	// Somebody else's access changes as it always did, and a narrow deny on
	// the last administrator leaves them administering the store.
	if err := cmdAuth(root, []string{"revoke", "sam", "viewer"}); err != nil {
		t.Errorf("revoking somebody else: %v", err)
	}
	if err := cmdAuth(root, []string{"deny", "dana", "viewer", "--on", "/@log"}); err != nil {
		t.Errorf("a deny on one area of the last administrator: %v", err)
	}
}

// With a second administrator, either may step down, and the one left is
// then the last.
func TestAnAdministratorMayStepDownWhileAnotherRemains(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"lee", "admin"})
	asOnly(t, root, "lee")
	if err := cmdAuth(root, []string{"revoke", "lee", "admin"}); err != nil {
		t.Fatalf("an administrator stepping down while another remains: %v", err)
	}
	asOnly(t, root, "dana")
	if err := cmdAuth(root, []string{"revoke", "dana", "admin"}); err == nil ||
		!strings.Contains(err.Error(), "last administrator") {
		t.Errorf("the one left then stepped down: %v", err)
	}
	// A store that never had an administrator is not held to having one:
	// there is nobody to lock out.
	empty := t.TempDir()
	seedPolicy(t, empty, [2]string{"sam", "viewer"})
	if _, err := updatePolicy(empty, func(p *auth.Policy) error {
		p.Revoke("sam", auth.RoleViewer, "/")
		return nil
	}); err != nil {
		t.Errorf("a store with no administrator to keep: %v", err)
	}
}

// An identity provider cannot take the last administrator's administration
// away either: provisioning writes through the same check, so a group
// removed or a person deactivated there is refused while nobody else
// administers the store, and they keep it.
func TestProvisioningCannotRemoveTheLastAdministrator(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"sam", "viewer"})
	if err := scimSync(root, "ada@acme.example", []string{"admin"}, false); err != nil {
		t.Fatalf("provisioning the first administrator: %v", err)
	}
	for name, sync := range map[string]func() error{
		"removed from the group": func() error { return scimSync(root, "ada@acme.example", nil, false) },
		"deactivated":            func() error { return scimSync(root, "ada@acme.example", []string{"admin"}, true) },
	} {
		if err := sync(); err == nil || !strings.Contains(err.Error(), "last administrator") {
			t.Errorf("the last administrator %s: %v", name, err)
		}
	}
	if p, _ := loadPolicy(root); !p.Evaluate("ada@acme.example", auth.ActGrant, "/").Allowed {
		t.Error("provisioning left the store with nobody to administer it")
	}
}
