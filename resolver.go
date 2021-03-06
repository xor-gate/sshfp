// Copyright 2018 sshfp authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package sshfp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

// Resolver resolves DNS SSHFP records
type Resolver struct {
	c  Cache
	cc *dns.ClientConfig
}

// ResolverOption for Resolver
type ResolverOption func(*Resolver) error

// NewResolver creates a new DNS SSHFP resolver
func NewResolver(opts ...ResolverOption) (*Resolver, error) {
	r := &Resolver{}
	for _, option := range opts {
		err := option(r)
		if err != nil {
			return nil, err
		}
	}

	// Check if a cache is attached, or else we attach one
	if r.c == nil {
		c, err := NewMemoryCache()
		if err != nil {
			return nil, err
		}
		r.c = c
	}

	return r, nil
}

// WithCache sets a Cache for the Resolver
func WithCache(c Cache) ResolverOption {
	return func(r *Resolver) error {
		r.c = c
		return nil
	}
}

// WithDNSClientConfigFromFile loads a resolv.conf(5) like file
func WithDNSClientConfigFromFile(resolvconf string) ResolverOption {
	return func(r *Resolver) error {
		cc, err := dns.ClientConfigFromFile(resolvconf)
		if err != nil {
			return err
		}
		r.cc = cc
		return nil
	}
}

// WithDNSClientConfigFromReader works like WithDNSClientConfigFromFile but takes an io.Reader as argument
func WithDNSClientConfigFromReader(resolvconf io.Reader) ResolverOption {
	return func(r *Resolver) error {
		cc, err := dns.ClientConfigFromReader(resolvconf)
		if err != nil {
			return err
		}
		r.cc = cc
		return nil
	}
}

// checkCache checks the cache for a valid fingerprint
func (r *Resolver) checkCache(hostname string, key ssh.PublicKey) error {
	centries, ok := r.c.Get(hostname, AlgorithmFromSSHPublicKey(key))
	if ok {
		for _, ce := range centries {
			if ce.IsExpired() {
				err := r.c.Remove(ce)
				if err != nil {
					return err
				}
				continue
			}
			if ce.Validate(key) {
				return nil
			}
		}
		return ErrHostKeyChanged
	}
	return ErrNoHostKeyFound
}

// HostKeyCallback with DNS SSHFP entry verification for golang.org/x/crypto/ssh
func (r *Resolver) HostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	hostURL, err := ParseHostname(hostname)
	if err != nil {
		return err
	}
	hostname = hostURL.Hostname()

	// lookup cache
	err = r.checkCache(hostname, key)
	switch err {
	case ErrNoHostKeyFound:
		break
	case nil:
		return nil
	default:
		return err
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
		fp, err := hex.DecodeString(entry.FingerPrint)
		if err != nil {
			continue
		}

		if !bytes.Equal(fp, keyFpSHA256[:]) {
			continue
		}

		expiresAt := time.Now().Add(time.Duration(entry.Hdr.Ttl) * time.Second)
		e := &Entry{
			SSHFP:       entry,
			ExpiresAt:   expiresAt,
			Hostname:    hostname,
			Fingerprint: fp,
		}

		return r.c.Add(e)
	}

	return ErrNoHostKeyFound
}

// LookupHost looks up the given host for DNS SSHFP records
func (r *Resolver) LookupHost(hostname string) ([]*dns.SSHFP, error) {
	if r.cc == nil {
		return nil, ErrNoDNSServer
	}
	if len(r.cc.Servers) == 0 {
		return nil, ErrNoDNSServer
	}

	c := new(dns.Client)
	m := new(dns.Msg)

	m.SetQuestion(dns.Fqdn(hostname), dns.TypeSSHFP)
	m.RecursionDesired = true

	// TODO error on no DNS servers
	// TODO loop over r.cc.Servers instead of first entry
	resp, _, err := c.Exchange(m, net.JoinHostPort(r.cc.Servers[0], r.cc.Port))
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
