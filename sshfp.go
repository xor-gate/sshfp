package sshfp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

// Resolver resolves DNS SSHFP records
type Resolver struct {
	c Cache
}

// ResolverOption for Resolver
type ResolverOption func(*Resolver)

// NewResolver creates a new DNS SSHFP resolver
func NewResolver(opts ...ResolverOption) (*Resolver, error) {
	r := &Resolver{}
	for _, option := range opts {
		option(r)
	}

	// Check if a cache is attached, or else we attach one
	if r.c == nil {
		cache, err := NewMemoryCache(1024)
		if err != nil {
			return nil, err
		}
		r.c = cache
	}

	return r, nil
}

// WithCache sets a Cache for the Resolver
func WithCache(c Cache) ResolverOption {
	return func(r *Resolver) {
		r.c = c
	}
}

// HostKeyCallback with DNS SSHFP entry verification for golang.org/x/crypto/ssh
func (r *Resolver) HostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	// lookup cache
	ce, ok := r.c.Get(hostname)
	if ok {
		if !ce.IsExpired() {
			if ce.IsSSHPublicKeyValid(key) {
				return nil
			} else {
				return fmt.Errorf("sshfp: host key changed")
			}
		} else {
			r.c.Remove(ce)
		}
	}

	// lookup dns
	entries, err := r.LookupHost(hostname)
	if err != nil {
		return err
	}

	// SHA256 checksum of key
	// TODO should also support other algos
	keyFpSHA256 := sha256.Sum256(key.Marshal())

	// TODO very naive way to validate, we should match on key type and algo
	//      and don't brute force check
	for _, entry := range entries {
		fp, _ := hex.DecodeString(entry.FingerPrint)
		if !bytes.Equal(fp, keyFpSHA256[:]) {
			continue
		}

		expiresAt := time.Now().Add(time.Duration(entry.Hdr.Ttl) * time.Second)
		fmt.Println("expiresAt", expiresAt)
		e := &Entry{
			SSHFP:       entry,
			ExpiresAt:   expiresAt,
			Hostname:    hostname,
			Fingerprint: fp,
		}
		r.c.Add(e)
		return nil
	}
	return fmt.Errorf("sshfp: no host key found")
}

// LookupHost looks up the given host for DNS SSHFP records
func (r *Resolver) LookupHost(host string) ([]*dns.SSHFP, error) {
	c := new(dns.Client)
	m := new(dns.Msg)

	// TODO: to ugly hack to be able to parse "shulgin.xor-gate.org:6222" ...
	hostURL, err := url.Parse("tcp://" + host)
	if err != nil {
		return nil, err
	}

	m.SetQuestion(dns.Fqdn(hostURL.Hostname()), dns.TypeSSHFP)
	m.RecursionDesired = true
	resp, _, err := c.Exchange(m, net.JoinHostPort("ns1.transip.nl", "53"))

	if err != nil {
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("sshfp: DNS error (Rcode %d)", resp.Rcode)
	}

	var l []*dns.SSHFP

	for _, a := range resp.Answer {
		sshfp, ok := a.(*dns.SSHFP)
		if !ok {
			continue
		}
		l = append(l, sshfp)
	}
	return l, nil
}

// IsSSHPublicKeyValid checks if the key is valid
func (e *Entry) IsSSHPublicKeyValid(key ssh.PublicKey) bool {
	if e.Fingerprint == nil {
		return false
	}
	fp := sha256.Sum256(key.Marshal())
	return bytes.Equal(e.Fingerprint, fp[:])
}

// TTL calculates the remaining seconds the entry is valid
func (e *Entry) TTL() uint32 {
	return uint32(e.ExpiresAt.Sub(time.Now()) / time.Second)
}

// IsExpired checks if the entry is expired
func (e *Entry) IsExpired() bool {
	fmt.Println("TTL:", e.TTL())
	return time.Now().After(e.ExpiresAt)
}
