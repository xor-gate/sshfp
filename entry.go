package sshfp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

// Entry wraps a DNS SSHFP entry used for caching
type Entry struct {
	*dns.SSHFP
	ExpiresAt   time.Time
	Hostname    string
	Fingerprint []byte
}

// IsSSHPublicKeyValid checks if the key is valid
func (e *Entry) IsSSHPublicKeyValid(key ssh.PublicKey) bool {
	if e.Fingerprint == nil {
		return false
	}
	fp := sha256.Sum256(key.Marshal())
	return bytes.Equal(e.Fingerprint, fp[:])
}

// TTL calculates the remaining seconds the entry is valid. When ExpiresAt field is zero then it
//  never expires and returns math.MaxUint32.
func (e *Entry) TTL() uint32 {
	if e.ExpiresAt.IsZero() {
		return math.MaxUint32
	}
	ttl := time.Until(e.ExpiresAt)
	if ttl < 1 {
		return 0
	}
	return uint32(ttl / time.Second)
}

// IsExpired checks if the entry is expired
func (e *Entry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt)
}

// IsValid checks if the entry is valid
func (e *Entry) IsValid() bool {
	return true
}

// String creates a human readable presentation of the SSHFP entry
// <hostname> <algorithm string> <fingerprint type string>
func (e *Entry) String() string {
	return fmt.Sprintf("%s %s %s", e.Hostname, Algorithm(e.SSHFP.Algorithm), Type(e.SSHFP.Type))
}
