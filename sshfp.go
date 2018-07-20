package sshfp

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

// ErrHostKeyChanged when the SSH server host key has changed
var ErrHostKeyChanged = fmt.Errorf("sshfp: host key changed")

// ErrNoHostKeyFound when no host key is found in DNS (or cache)
var ErrNoHostKeyFound = fmt.Errorf("sshfp: no host key found")

// SSHURLScheme is the URL scheme for SSH host urls
const SSHURLScheme = "ssh://"

// Algorithm of the host public key
type Algorithm uint8

// golint: nolint
const (
	AlgorithmReserved Algorithm = 0
	AlgorithmRSA      Algorithm = 1
	AlgorithmDSS      Algorithm = 2
	AlgorithmECDSA    Algorithm = 3
	AlgorithmEd25519  Algorithm = 4
)

// Type of the fingerprint checksum
type Type uint8

// golint: nolint
const (
	TypeReserved Type = 0
	TypeSHA1     Type = 1
	TypeSHA256   Type = 2
)

// String gets the algorithm string as defined in RFC. Reserved or unknown algorithms return "reserved"
func (a Algorithm) String() string {
	switch a {
	case AlgorithmRSA:
		return "RSA"
	case AlgorithmDSS:
		return "DSS"
	case AlgorithmECDSA:
		return "ECDSA"
	case AlgorithmEd25519:
		return "Ed25519"
	}
	return "reserved"
}

// String gets the fingerprint type string as defined in RFC. Reserved or unknown algorithms return "reserved"
func (fp Type) String() string {
	switch fp {
	case TypeSHA1:
		return "SHA-1"
	case TypeSHA256:
		return "SHA-256"
	}
	return "reserved"
}

// ParseZone parses a RFC 1035 zonefile and creates a slice of Entry elements.
//  This is compatible with the entries ssh-keygen -r <hostname> generates.
func ParseZone(r io.Reader) ([]*Entry, error) {
	var entries []*Entry

	tokenC := dns.ParseZone(r, "", "")
	for token := range tokenC {
		if token.Error != nil {
			return nil, token.Error
		}

		r, ok := token.RR.(*dns.SSHFP)
		if !ok {
			continue
		}

		fingerprint, err := hex.DecodeString(r.FingerPrint)
		if err != nil {
			continue
		}

		e := &Entry{
			SSHFP:       r,
			Hostname:    strings.Join(dns.SplitDomainName(r.Hdr.Name), "."),
			Fingerprint: fingerprint,
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ParseHostname parses the hostname into a url.URL
func ParseHostname(hostname string) (*url.URL, error) {
	if !strings.HasPrefix(SSHURLScheme, hostname) {
		hostname = SSHURLScheme + hostname
	}
	return url.Parse(hostname)
}
