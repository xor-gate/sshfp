package sshfp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

type Resolver struct {
	cache Cache
}

type Option func(*Resolver)

func NewResolver(opts ...Option) *Resolver {
	r := &Resolver{}
	for _, option := range opts {
		option(r)
	}

	if r.cache == nil {
		r.cache = NewMemoryCache()
	}
	return r
}

func WithCache(c Cache) Option {
	return func(r *Resolver) {
		r.cache = c
	}
}

func (r *Resolver) HostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	r.cache.Get()

	l, err := r.Lookup(hostname)
	if err != nil {
		return err
	}

	keyFpSHA256 := sha256.Sum256(key.Marshal())

	for _, sshfp := range l {
		raw, _ := hex.DecodeString(sshfp.FingerPrint)

		// Check if there is a match
		if bytes.Equal(keyFpSHA256[:], raw) {
			r.cache.Set()
			return nil
		}
	}

	return fmt.Errorf("sshfp: no host key found")
}

func (r *Resolver) Lookup(host string) ([]*dns.SSHFP, error) {
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
