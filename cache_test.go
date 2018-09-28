// Copyright 2018 sshfp authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package sshfp

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryCache(t *testing.T) {
	c, err := NewMemoryCache()
	require.Nil(t, err)
	require.NotNil(t, c)
	entry := &Entry{SSHFP: &dns.SSHFP{}, Hostname: "ssh.example.com"}
	assert.Nil(t, c.Add(entry))
	assert.Len(t, c.c, 1)
	assert.Len(t, c.c["ssh.example.com"], 1)
	assert.Nil(t, c.Remove(entry))
}
