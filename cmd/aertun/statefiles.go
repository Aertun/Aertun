// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/auth"
)

// The state files where a lost write undoes a security decision: who may
// do what, and which credentials are live. Each is changed under its lock,
// on what is stored at that moment (atomicfile.Update), rather than loaded
// early and written back whole later.

// updatePolicy changes the access policy as it is stored now, and returns
// it as it was written. Every surface's access change comes through here —
// the command line, the admin, provisioning — so this is where the Owner
// is kept (auth.Policy.CheckOwner), and its last administrator
// (CheckAdministered): a change that would leave the store's Owner without
// it, or the store with nobody to administer it, is refused before anything
// is written.
func updatePolicy(root string, change func(*auth.Policy) error) (*auth.Policy, error) {
	var out *auth.Policy
	err := atomicfile.Update(policyPath(root), func(p *auth.Policy) error {
		out = p
		before := p.Administrators()
		if err := change(p); err != nil {
			return err
		}
		if err := p.CheckOwner(); err != nil {
			return err
		}
		// And the store still has an administrator, Owner or not: a store
		// made before Owners, or one whose Owner is not yet named, is kept
		// from being locked out the same way.
		return p.CheckAdministered(before)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// saveTokens writes a token store merged with the one stored now, so a
// token added or revoked elsewhere since ts was read is neither lost nor
// brought back (auth.TokenStore.MergeInto).
func saveTokens(root string, ts *auth.TokenStore) error {
	return atomicfile.Update(tokensPath(root), func(stored *auth.TokenStore) error {
		ts.MergeInto(stored, time.Now())
		return nil
	})
}
