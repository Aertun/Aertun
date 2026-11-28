// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package benign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/aertun/aertun/internal/pii"
	"github.com/aertun/aertun/internal/secret"
	"github.com/aertun/aertun/internal/telemetry"
)

// PolicyVersion names the sanitising rules below. A bundle records it, so a
// session sanitised by an older version is never compared as though it were
// sanitised by this one.
const PolicyVersion = "aertun/benign-sanitise/v1"

// Structural are the fields every sanitised event keeps whatever the rules
// read: when it happened and arrived, where it came from, and its class,
// activity, severity and disposition. They carry no identity.
var Structural = []string{"source", "class", "activity", "severity", "disposition"}

// Interpretive are raw fields kept whatever the rules read because they say
// how another field is to be read: the shell a command line runs in decides
// what its quoting means, so a respelling of it (the wind tunnel's
// mutation) is only sound with it. They name nobody.
var Interpretive = []string{"raw.shell"}

// PublicDomains are registrable domains of public services, kept as they are
// because they name a provider, not a person or an organisation: a rule
// about "anything from amazonaws.com" needs them, and the labels to their
// left — an organisation's own bucket or tenant — are still pseudonymised.
var PublicDomains = []string{
	"amazonaws.com", "cloudfront.net", "azure.com", "windows.net", "microsoft.com",
	"microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com",
	"google.com", "googleapis.com", "gstatic.com", "gcr.io", "gmail.com",
	"github.com", "githubusercontent.com", "ghcr.io", "gitlab.com", "docker.io",
	"docker.com", "npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org",
	"golang.org", "go.dev", "okta.com", "slack.com", "cloudflare.com",
	"openai.com", "anthropic.com", "huggingface.co", "apple.com", "icloud.com",
	"ubuntu.com", "debian.org", "yahoo.com", "hotmail.com", "proton.me",
	"s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com",
}

// identityKeys are the words that mark a raw field as naming somebody or
// something: a value under such a key is pseudonymised whole, by its shape.
var identityKeys = map[string]bool{
	"user": true, "username": true, "email": true, "mail": true, "principal": true,
	"account": true, "login": true, "ip": true, "ipaddress": true, "host": true,
	"hostname": true, "computer": true, "device": true, "machine": true,
	"workstation": true, "caller": true, "owner": true, "actor": true, "client": true,
	"src": true, "dst": true, "remote": true, "peer": true, "upn": true, "sid": true,
}

// Sanitiser turns raw events into ones fit to leave the store.
//
// It is deterministic for a key: the same value always becomes the same
// pseudonym, so equalities survive — across events, sessions and bundles
// made with one key — and nothing else does.
type Sanitiser struct {
	key []byte
	// Keep are the fields a rule may read; nil keeps every field.
	Keep map[string]bool
	// Raw are fields kept as they are, at the operator's recorded request.
	Raw map[string]bool

	cache  map[string]string
	ips    map[netip.Addr]netip.Addr
	masker *pii.Masker
}

// NewSanitiser makes a sanitiser over a key of at least 32 bytes.
func NewSanitiser(key []byte, keep, raw map[string]bool) (*Sanitiser, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("a pseudonym key is at least 32 bytes")
	}
	return &Sanitiser{key: append([]byte(nil), key...), Keep: keep, Raw: raw,
		cache: map[string]string{}, ips: map[netip.Addr]netip.Addr{},
		masker: &pii.Masker{Secrets: secret.Spans}}, nil
}

// KeyID names a pseudonym key without revealing it, so two bundles can be
// seen to share one — and their pseudonyms to be comparable — or not.
func KeyID(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("aertun/benign-key-id/v1"))
	return fmt.Sprintf("%x", m.Sum(nil)[:16])
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func (s *Sanitiser) mac(kind, v string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(v))
	return m.Sum(nil)
}

// token is a pseudonym for v of a kind: lower-case letters and digits, the
// same for the same key, kind and value.
func (s *Sanitiser) token(kind, v string) string {
	k := kind + "\x00" + v
	if t, ok := s.cache[k]; ok {
		return t
	}
	t := strings.ToLower(b32.EncodeToString(s.mac(kind, v)[:8]))
	s.cache[k] = t
	return t
}

// Person is the pseudonym a person is named by in a bundle.
func (s *Sanitiser) Person(name string) string { return "p-" + s.token("person", name) }

// Opaque is a pseudonym for a value of a kind that keeps no shape at all.
func (s *Sanitiser) Opaque(kind, v string) string { return "p-" + s.token(kind, v) }

// Domain keeps a domain's shape: each label but the last is pseudonymised on
// its own, so x.corp.example and y.corp.example still share a parent; a
// public provider's registrable domain is kept, with the labels to its left
// pseudonymised.
func (s *Sanitiser) Domain(d string) string {
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	if d == "" || d == "localhost" {
		return d
	}
	labels := strings.Split(d, ".")
	if len(labels) == 1 {
		return "h" + s.token("label", d)[:10]
	}
	// The longest public domain it is under: s3.amazonaws.com before
	// amazonaws.com, so the service stays named and only the tenant goes.
	keep := 1
	for _, pub := range PublicDomains {
		if n := strings.Count(pub, ".") + 1; n > keep && (d == pub || strings.HasSuffix(d, "."+pub)) {
			keep = n
		}
	}
	for i := 0; i < len(labels)-keep; i++ {
		labels[i] = "d" + s.token("label", labels[i])[:10]
	}
	return strings.Join(labels, ".")
}

// Email pseudonymises the person and keeps the domain's shape.
func (s *Sanitiser) Email(e string) string {
	at := strings.LastIndexByte(e, '@')
	if at <= 0 || at == len(e)-1 {
		return s.Opaque("value", e)
	}
	return "p-" + s.token("local", strings.ToLower(e[:at])) + "@" + s.Domain(e[at+1:])
}

// The special-purpose ranges an address stays inside when pseudonymised, so
// "private", "loopback" and "documentation" survive (RFC 6890 and its
// registries). An address outside every one is public, and stays public.
var (
	v4Special = prefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
	v6Special = prefixes("::/127", "64:ff9b::/96", "100::/64", "2001:db8::/32",
		"fc00::/7", "fe80::/10", "ff00::/8")
	v6Global = netip.MustParsePrefix("2000::/3")
)

func prefixes(ps ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ps))
	for i, p := range ps {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func specialOf(a netip.Addr) (netip.Prefix, bool) {
	list := v6Special
	if a.Is4() {
		list = v4Special
	}
	for _, p := range list {
		if p.Contains(a) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// IP pseudonymises an address, prefix-preserving: two addresses sharing an
// n-bit prefix share an n-bit prefix afterwards (the Crypto-PAn construction,
// with HMAC-SHA-256 as the function), and an address in a special-purpose
// range stays in it. A public IPv4 address that lands in a special range is
// drawn again, so it stays public; that one draw gives up prefix
// preservation for it, and nothing else.
func (s *Sanitiser) IP(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if out, ok := s.ips[a]; ok {
		return out
	}
	fixed := 0
	if p, ok := specialOf(a); ok {
		fixed = p.Bits()
	} else if a.Is6() && v6Global.Contains(a) {
		fixed = v6Global.Bits()
	}
	out := s.scramble(a, fixed, 0)
	if a.Is4() && fixed == 0 {
		for draw := 1; draw < 64; draw++ {
			if _, special := specialOf(out); !special {
				break
			}
			out = s.scramble(a, 0, draw)
		}
	}
	s.ips[a] = out
	return out
}

func (s *Sanitiser) scramble(a netip.Addr, fixed, draw int) netip.Addr {
	raw := a.AsSlice()
	bits := len(raw) * 8
	out := make([]byte, len(raw))
	copy(out, raw)
	prefix := make([]byte, len(raw))
	for i := fixed; i < bits; i++ {
		m := hmac.New(sha256.New, s.key)
		var hdr [6]byte
		hdr[0] = byte(len(raw))
		binary.BigEndian.PutUint16(hdr[1:3], uint16(draw))
		binary.BigEndian.PutUint16(hdr[3:5], uint16(i))
		m.Write([]byte("aertun/benign-ip/v1"))
		m.Write(hdr[:])
		// The input's first i bits, the rest zero.
		copy(prefix, raw)
		for b := i; b < bits; b++ {
			prefix[b/8] &^= 0x80 >> (b % 8)
		}
		m.Write(prefix)
		if m.Sum(nil)[0]&1 == 1 {
			out[i/8] ^= 0x80 >> (i % 8)
		}
	}
	addr, _ := netip.AddrFromSlice(out)
	return addr
}

var (
	homeSegment = regexp.MustCompile(`(?i)(/home/|/users/|\\users\\)([^/\\\s"'` + "`" + `]+)`)
	emailShape  = regexp.MustCompile(`\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b`)
	placeholder = regexp.MustCompile(`<aertun:([a-z-]+):\d+>`)
)

// Path pseudonymises the person in a path — the segment after /home/,
// /Users/ or \Users\ — and keeps the rest, because what a path says about a
// workflow is in its shape and its file names.
func (s *Sanitiser) Path(p string) string {
	return homeSegment.ReplaceAllStringFunc(p, func(m string) string {
		sub := homeSegment.FindStringSubmatch(m)
		return sub[1] + "u" + s.token("user", strings.ToLower(sub[2]))[:10]
	})
}

// Text masks what free text must not carry: credentials, card and bank
// numbers, national identifiers and telephone numbers become keyed
// placeholders, the same everywhere for the same value; email addresses
// become their pseudonyms; and the person in a home path is pseudonymised.
// Everything else — the command, its flags, its file names — stays, because
// it is what a rule reads.
func (s *Sanitiser) Text(t string) string {
	if t == "" {
		return t
	}
	t = emailShape.ReplaceAllStringFunc(t, s.Email)
	allowed := map[string]bool{}
	for _, m := range emailShape.FindAllString(t, -1) {
		allowed[strings.ToLower(m[strings.LastIndexByte(m, '@')+1:])] = true
	}
	s.masker.Allowed = s.masker.Allowed[:0]
	for d := range allowed {
		s.masker.Allowed = append(s.masker.Allowed, d)
	}
	t = s.masker.Mask(t, false)
	t = placeholder.ReplaceAllStringFunc(t, func(ph string) string {
		kind := placeholder.FindStringSubmatch(ph)[1]
		orig := s.masker.Restore(ph)
		if orig == ph {
			return ph
		}
		return "<" + kind + ":" + s.token("masked-"+kind, orig)[:10] + ">"
	})
	return s.Path(t)
}

// value pseudonymises a whole value by what it looks like.
func (s *Sanitiser) value(v string) string {
	if v == "" {
		return v
	}
	if a, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil && a.Zone() == "" {
		return s.IP(a).String()
	}
	if strings.Count(v, "@") == 1 && emailShape.MatchString(v) {
		return s.Email(v)
	}
	if looksDomain(v) {
		return s.Domain(v)
	}
	return s.Opaque("value", v)
}

func looksDomain(v string) bool {
	if !strings.Contains(v, ".") || strings.ContainsAny(v, " /\\:@") || len(v) > 253 {
		return false
	}
	last := v[strings.LastIndexByte(v, '.')+1:]
	if len(last) < 2 {
		return false
	}
	for _, r := range last {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// URL keeps a URL's scheme, path shape and query keys; the host becomes its
// pseudonym, a person in the path is pseudonymised, and query values are
// masked as free text.
func (s *Sanitiser) URL(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return s.Text(v)
	}
	host, port := u.Hostname(), u.Port()
	if a, perr := netip.ParseAddr(host); perr == nil {
		host = s.IP(a).String()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else {
		host = s.Domain(host)
	}
	if port != "" {
		host += ":" + port
	}
	u.Host = host
	u.User = nil
	u.Path = s.Path(u.Path)
	u.RawPath = ""
	if u.RawQuery != "" {
		q := u.Query()
		for k, vs := range q {
			for i := range vs {
				vs[i] = s.Text(vs[i])
			}
			q[k] = vs
		}
		u.RawQuery = q.Encode()
	}
	u.Fragment = ""
	return u.String()
}

// keyWords splits a raw field's key into its words, by punctuation and by
// case: sourceIPAddress is source, ip, address.
func keyWords(k string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(k)
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) ||
			(i+1 < len(rs) && unicode.IsLower(rs[i+1]) && unicode.IsUpper(rs[i-1]))):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}

func identityKey(k string) bool {
	for _, w := range keyWords(k) {
		if identityKeys[w] {
			return true
		}
	}
	return false
}

func (s *Sanitiser) kept(field string) bool { return s.Keep == nil || s.Keep[field] }

func (s *Sanitiser) raw(field string) bool { return s.Raw[field] }

// Event sanitises one event. It answers the event, the fields whose value it
// changed, and the fields the event carried that it dropped, each by the
// name rules read it by.
func (s *Sanitiser) Event(e telemetry.Event) (out telemetry.Event, changed, dropped []string) {
	set := func(field, before, after string) string {
		if before != after {
			changed = append(changed, field)
		}
		return after
	}
	out = telemetry.Event{Time: e.Time.UTC(), Received: e.Received.UTC(), Class: e.Class,
		Activity: e.Activity, Severity: e.Severity, Disposition: e.Disposition, Source: e.Source}
	switch {
	case e.Message == "":
	case !s.kept("message"):
		dropped = append(dropped, "message")
	case s.raw("message"):
		out.Message = e.Message
	default:
		out.Message = set("message", e.Message, s.Text(e.Message))
	}
	for _, id := range []struct {
		name string
		in   telemetry.ID
		out  *telemetry.ID
	}{{"actor", e.Actor, &out.Actor}, {"target", e.Target, &out.Target}, {"device", e.Device, &out.Device}} {
		if id.in.Zero() {
			continue
		}
		v := id.in.Value
		if !s.raw(id.name + ".value") {
			v = set(id.name+".value", id.in.Value, s.value(id.in.Value))
		}
		*id.out = telemetry.ID{Issuer: id.in.Issuer, Value: v}
	}
	for _, o := range e.Observables {
		kind := o.Kind.String()
		if !s.kept(kind) {
			dropped = append(dropped, kind)
			continue
		}
		v := o.Value
		if !s.raw(kind) {
			switch o.Kind {
			case telemetry.ObservableIP:
				if a, err := netip.ParseAddr(v); err == nil {
					v = s.IP(a).String()
				} else {
					v = s.Opaque("value", v)
				}
			case telemetry.ObservableHostname, telemetry.ObservableDomain:
				v = s.Domain(v)
			case telemetry.ObservableEmail:
				v = s.Email(v)
			case telemetry.ObservableURL:
				v = s.URL(v)
			case telemetry.ObservableFile, telemetry.ObservableProcess:
				v = s.Text(v)
			case telemetry.ObservableHash, telemetry.ObservablePort, telemetry.ObservableUserAgent:
			default:
				v = s.Text(v)
			}
			v = set(kind, o.Value, v)
		}
		out.Observables = append(out.Observables, telemetry.Observable{Kind: o.Kind, Value: v, Name: o.Name})
	}
	for k, v := range e.Raw {
		field := "raw." + k
		if !s.kept(field) {
			dropped = append(dropped, field)
			continue
		}
		if out.Raw == nil {
			out.Raw = map[string]string{}
		}
		switch {
		case s.raw(field):
			out.Raw[k] = v
		case identityKey(k):
			out.Raw[k] = set(field, v, s.value(v))
		case strings.Contains(v, "://"):
			out.Raw[k] = set(field, v, s.URL(v))
		default:
			out.Raw[k] = set(field, v, s.Text(v))
		}
	}
	sort.Strings(changed)
	sort.Strings(dropped)
	return out, dedupe(changed), dedupe(dropped)
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// FieldsOf are the field names a list of events carries, sorted, by the
// names rules read them by.
func FieldsOf(events []telemetry.Event) []string {
	seen := map[string]bool{}
	for _, e := range events {
		for f, v := range e.Fields() {
			if f == "message" && v == "" {
				continue
			}
			seen[f] = true
		}
	}
	for _, f := range Structural {
		seen[f] = true
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
