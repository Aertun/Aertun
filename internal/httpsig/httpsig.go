// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package httpsig signs and verifies HTTP requests under RFC 9421, with
// Ed25519.
//
// # What uses it
//
// One deployment's audit stream signs every batch it sends, and another's
// receiver checks it (internal/auditstream). The sender and the receiver are
// both this program, so there is one wire format and one algorithm: nothing
// here reads an older draft of the standard or a key of another kind, because
// a format nobody sends is only something to get wrong.
//
// # What is here and what is not
//
// The signature base, the header parsing, signing and verification, and the
// body digest a signature covers. Not here: who a key belongs to, or whether
// that identity may do anything. Those are the caller's decisions.
//
// # The rule that makes verification mean anything
//
// A covered component that cannot be rebuilt is refused, never skipped.
//
// Skipping one means checking a signature over less than was signed and
// reporting the result as valid — a forgery the verifier performs on itself,
// and the only one it cannot be warned about by anybody else.
package httpsig

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Algorithm names the signing algorithm, using RFC 9421's own registry names.
type Algorithm string

// Ed25519 is the one algorithm signed with and checked.
const Ed25519 Algorithm = "ed25519"

// DefaultMaxAge bounds how old a signature may be.
//
// A signature over components that do not change authenticates forever
// without one, so a request captured from a log replays indefinitely.
const DefaultMaxAge = 5 * time.Minute

// PublicKey is a key a signature can be checked against.
type PublicKey struct {
	// ID is the keyid a signature names.
	ID string
	// Alg is what the key signs with. Held rather than read from the
	// signature: an attacker who could choose the algorithm could choose a
	// weaker one, and "the signature said so" is not a reason to believe it.
	Alg Algorithm
	// Ed is the key.
	Ed ed25519.PublicKey
}

// errNoKeys is a signed request with nothing to check it against.
var errNoKeys = fmt.Errorf(
	"a request is signed and no keys are configured, so it cannot be " +
		"checked. An unverifiable signature is not an identity")

// Signed describes a verified signature.
type Signed struct {
	// KeyID is the key that verified it.
	KeyID string
	// Created is when it was made.
	Created time.Time
	// Covered lists the components the signature was over, so a caller can
	// require that something in particular was signed.
	Covered []string
}

// Covers reports whether a component was part of what was signed.
//
// Worth asking. A signature over "@method" alone is a valid signature and
// proves almost nothing about the request it arrived on, so a caller that
// cares about the body has to check the body was covered.
func (s Signed) Covers(component string) bool {
	for _, c := range s.Covered {
		if strings.EqualFold(c, component) {
			return true
		}
	}
	return false
}

// Verify checks a request's signature against a set of known keys.
//
// Returns nil, nil for a request carrying no signature at all — the ordinary
// case for a browser, and not a failure to report.
func Verify(r *http.Request, keys []PublicKey, maxAge time.Duration,
	now time.Time) (*Signed, error) {

	return VerifyAt(r, "", keys, maxAge, now)
}

// VerifyAt is Verify for a server that knows its own public origin, which is
// what rebuilding @target-uri on an inbound request needs. See BaseAt.
func VerifyAt(r *http.Request, origin string, keys []PublicKey,
	maxAge time.Duration, now time.Time) (*Signed, error) {

	input := r.Header.Get("Signature-Input")
	sig := r.Header.Get("Signature")
	if input == "" && sig == "" {
		return nil, nil
	}
	// Both headers, or it is not an RFC 9421 signature. A Signature with
	// no Signature-Input is how the draft before the standard was written,
	// which nothing that sends here uses and nothing here reads.
	if input == "" || sig == "" {
		return nil, fmt.Errorf(
			"this request carries one half of a signature. Signature-Input " +
				"and Signature are both required, and half of a proof is not " +
				"a weaker proof, it is none")
	}
	if len(keys) == 0 {
		return nil, errNoKeys
	}

	label, params, err := parseInput(input)
	if err != nil {
		return nil, err
	}
	raw, err := parseSignature(sig, label)
	if err != nil {
		return nil, err
	}

	// Age before cryptography, on a cheap comparison, so replaying a captured
	// request does not cost a verification each time.
	created, err := strconv.ParseInt(params["created"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf(
			"this signature has no usable created time, so its age cannot be " +
				"checked and it has to be refused")
	}
	when := time.Unix(created, 0)
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if age := now.Sub(when); age > maxAge {
		return nil, fmt.Errorf("this signature was made %s ago, limit %s",
			age.Round(time.Second), maxAge)
	}
	if when.Sub(now) > time.Minute {
		return nil, fmt.Errorf("this signature is dated in the future")
	}
	if exp := params["expires"]; exp != "" {
		if s, perr := strconv.ParseInt(exp, 10, 64); perr == nil &&
			now.After(time.Unix(s, 0)) {
			return nil, fmt.Errorf("this signature has expired")
		}
	}

	keyID := params["keyid"]
	if keyID == "" {
		return nil, fmt.Errorf(
			"this signature names no key, so there is nothing to check it with")
	}
	var key *PublicKey
	for i := range keys {
		if keys[i].ID == keyID {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("key %q is not one this server knows", keyID)
	}

	base, covered, err := BaseAt(r, origin, params["components"], input)
	if err != nil {
		return nil, err
	}
	if err := verifyWith(*key, []byte(base), raw); err != nil {
		return nil, err
	}
	return &Signed{KeyID: keyID, Created: when, Covered: covered}, nil
}

// verifyWith checks the bytes against whichever algorithm the key declares.
//
// The key's algorithm, never the signature's. A verifier that took `alg` from
// the message lets the sender choose how their signature is checked, which is
// the algorithm-confusion bug that has been rediscovered in every signature
// format that allowed it.
func verifyWith(key PublicKey, base, sig []byte) error {
	switch key.Alg {
	case Ed25519:
		if key.Ed == nil {
			return fmt.Errorf("key %q declares ed25519 and carries no ed25519 key", key.ID)
		}
		if !ed25519.Verify(key.Ed, base, sig) {
			return fmt.Errorf(
				"the signature does not verify against the key it names")
		}
		return nil
	}
	return fmt.Errorf("key %q declares algorithm %q, which is not supported",
		key.ID, key.Alg)
}

// Sign adds a signature to an outbound request.
//
// The caller names which components to cover. There is no default, because a
// sensible default here depends entirely on what the receiver checks, and a
// signature that covers less than the receiver requires is refused with a
// message about signatures rather than about coverage.
func Sign(r *http.Request, keyID string, alg Algorithm, key crypto.Signer,
	components []string, now time.Time) error {

	if len(components) == 0 {
		return fmt.Errorf(
			"a signature covering nothing proves nothing; name the components")
	}
	params := fmt.Sprintf(`("%s");created=%d;keyid=%q;alg=%q`,
		strings.Join(components, `" "`), now.Unix(), keyID, alg)
	input := "sig1=" + params

	base, _, err := Base(r, strings.Join(quoteAll(components), " "), input)
	if err != nil {
		return err
	}

	sig, err := signWith(alg, key, []byte(base))
	if err != nil {
		return err
	}

	r.Header.Set("Signature-Input", input)
	r.Header.Set("Signature", "sig1=:"+encodeSignature(sig)+":")
	return nil
}

// signWith produces a signature over bytes with the named algorithm.
func signWith(alg Algorithm, key crypto.Signer, base []byte) ([]byte, error) {
	if alg != Ed25519 {
		return nil, fmt.Errorf("algorithm %q is not supported", alg)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ed25519 was named and the key is %T", key)
	}
	return ed25519.Sign(priv, base), nil
}

func encodeSignature(sig []byte) string {
	return base64.StdEncoding.EncodeToString(sig)
}

// targetURI rebuilds the absolute request URI.
//
// An outbound request carries an absolute URL already and is used as-is: that
// is a client signing what it is about to send. Otherwise this is an inbound
// request and the URL holds only a path, so the origin supplies the rest.
// Without a configured origin it falls back to the connection, which is right
// for a directly-served site and wrong behind a proxy -- and wrong here means
// a refused signature, never an accepted one.
func targetURI(r *http.Request, origin string) string {
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	if origin != "" {
		return strings.TrimSuffix(origin, "/") + r.URL.RequestURI()
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = `"` + s + `"`
	}
	return out
}

// Base rebuilds the signature base from a request, and reports what it covered.
//
// This is the whole of the check: if any covered component differs from what
// was signed, the base differs and the signature does not verify.
func Base(r *http.Request, components, input string) (string, []string, error) {
	return BaseAt(r, "", components, input)
}

// BaseAt is Base for a server that knows its own public origin.
//
// Only @target-uri needs it, and only inbound. Go fills r.URL from the
// request-target, which for an ordinary request is origin-form: a handler sees
// "/inbox", not "https://us.example/inbox". Rebuilding the target URI from
// that produces "/inbox" and a base that matches nothing the sender signed, so
// every signature covering @target-uri fails -- and @target-uri is what the
// audit stream signs.
//
// The origin comes from configuration rather than from the request. r.TLS is
// nil behind a TLS-terminating proxy, so deriving the scheme from it says
// "http" on a site served over https; X-Forwarded-Proto is written by whoever
// is talking to us. A site's public origin is a fact it already knows.
func BaseAt(r *http.Request, origin, components, input string) (string, []string, error) {
	var b strings.Builder
	var covered []string

	for _, raw := range strings.Fields(components) {
		name := strings.Trim(raw, `"`)
		var value string
		switch strings.ToLower(name) {
		case "@method":
			value = r.Method
		case "@authority":
			value = r.Host
		case "@path":
			value = r.URL.EscapedPath()
		case "@query":
			value = "?" + r.URL.RawQuery
		case "@target-uri":
			value = targetURI(r, origin)
		default:
			if strings.HasPrefix(name, "@") {
				return "", nil, fmt.Errorf(
					"this signature covers %q, which this program cannot "+
						"rebuild. Refusing rather than skipping it: a "+
						"signature checked over fewer components than were "+
						"signed is not the signature that was made", name)
			}
			value = r.Header.Get(name)
		}
		fmt.Fprintf(&b, "\"%s\": %s\n", strings.ToLower(name), value)
		covered = append(covered, strings.ToLower(name))
	}

	// The trailing line is the parameters exactly as they arrived. Rebuilding
	// them from a parsed map would let a difference between what was parsed
	// and what was sent pass unnoticed.
	_, rest, _ := strings.Cut(strings.TrimSpace(input), "=")
	fmt.Fprintf(&b, "\"@signature-params\": %s", strings.TrimSpace(rest))
	return b.String(), covered, nil
}

// parseInput reads the Signature-Input header.
//
// Deliberately small. A full structured-fields parser is a lot of code for a
// header shaped, in every implementation that exists, like
//
//	sig1=("@method" "@authority" "@path");created=123;keyid="k1";alg="ed25519"
//
// What it must not do is accept something it half-understood, so every field
// needed is required by the caller rather than defaulted here.
func parseInput(header string) (label string, params map[string]string, err error) {
	label, rest, found := strings.Cut(strings.TrimSpace(header), "=")
	if !found || strings.TrimSpace(label) == "" {
		return "", nil, fmt.Errorf("Signature-Input is not label=value")
	}
	label = strings.TrimSpace(label)

	open := strings.Index(rest, "(")
	shut := strings.Index(rest, ")")
	if open < 0 || shut < open {
		return "", nil, fmt.Errorf("Signature-Input names no covered components")
	}
	// An empty list parses and covers nothing: the base is the parameters
	// alone, so the signature authenticates the sender's key against any
	// request at all. Refused here rather than left to each caller to
	// remember, because a verifier that returns "valid" for a proof about
	// nothing is the forgery this package's own documentation warns about.
	if strings.TrimSpace(rest[open+1:shut]) == "" {
		return "", nil, fmt.Errorf(
			"this signature covers no components, so it proves possession of " +
				"a key and nothing about this request")
	}
	params = map[string]string{"components": rest[open+1 : shut]}
	for _, p := range strings.Split(rest[shut+1:], ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		params[strings.ToLower(strings.TrimSpace(k))] =
			strings.Trim(strings.TrimSpace(v), `"`)
	}
	return label, params, nil
}

// parseSignature pulls the bytes for this label out of the Signature header.
func parseSignature(header, label string) ([]byte, error) {
	for _, part := range strings.Split(header, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(name) != label {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.TrimSuffix(strings.TrimPrefix(value, ":"), ":")
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("the signature is not base64: %w", err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("the signature is empty")
		}
		return raw, nil
	}
	return nil, fmt.Errorf("the Signature header has no entry labelled %q", label)
}

// ContentDigest is the header name RFC 9421 uses to cover a request body.
const ContentDigest = "Content-Digest"

// SetContentDigest computes and sets the body digest on an outbound request.
//
// Signing a POST without covering the body is signing the envelope and not the
// letter: the signature says who sent *a* request to this path, and the body
// can then be replaced with anything. The digest is what puts the body inside
// what was signed, so it must be set before Sign and named in the components.
func SetContentDigest(r *http.Request, body []byte) {
	sum := sha256.Sum256(body)
	r.Header.Set(ContentDigest, "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
}

// CheckContentDigest verifies a request's Content-Digest against its body.
//
// A request with no digest at all is an error rather than a pass. This is
// called where the body must be covered, and "there was nothing to check" is
// how a body-swap gets through a check that looks like it happened.
func CheckContentDigest(r *http.Request, body []byte) error {
	sum := sha256.Sum256(body)
	want := base64.StdEncoding.EncodeToString(sum[:])

	raw := strings.TrimSpace(r.Header.Get(ContentDigest))
	if raw == "" {
		return fmt.Errorf(
			"this request carries no body digest, so the signature covers the " +
				"envelope and not the letter: a signature made for one body " +
				"would be accepted on another")
	}
	// sha-256=:base64:  — possibly among several algorithms.
	for _, part := range strings.Split(raw, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "sha-256") {
			continue
		}
		if strings.Trim(strings.TrimSpace(value), ":") == want {
			return nil
		}
		return fmt.Errorf("the Content-Digest does not match the body that arrived")
	}
	return fmt.Errorf("the Content-Digest names no sha-256 value this server can check")
}

// CheckSignedDigest verifies the body against the Content-Digest the
// signature covered, and refuses a signature that did not cover one.
//
// CheckContentDigest alone checks the header whether or not it was signed. A
// sender whose signature did not cover it could then have its body replaced
// by anybody on the way who wrote a Content-Digest of their own for the new
// body: the header matches and nobody signed it. Only what was signed
// counts.
func CheckSignedDigest(r *http.Request, body []byte, s *Signed) error {
	if s == nil {
		return errors.New("there is no signature to check the body against")
	}
	if !s.Covers(strings.ToLower(ContentDigest)) {
		return errors.New("this signature does not cover a body digest, so it says nothing about the body")
	}
	if strings.TrimSpace(r.Header.Get(ContentDigest)) == "" {
		return fmt.Errorf("the signature covers %s and the request has none", ContentDigest)
	}
	return CheckContentDigest(r, body)
}
