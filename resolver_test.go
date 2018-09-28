// Copyright 2018 sshfp authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package sshfp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolverPrefilledCache(t *testing.T) {
	entries := testParseZone(t, "example.sshfp.xor-gate.org.zone")
	assert.Len(t, entries, 8)

	mc, err := NewMemoryCache()
	require.Nil(t, err)
	require.Nil(t, mc.Add(entries...))
	require.Len(t, mc.c["example.sshfp.xor-gate.org"], 8)

	res, err := NewResolver(WithCache(mc))
	require.Nil(t, err)
	require.NotNil(t, res)

	pubKey := testParseAuthorizedKey(t, "ssh_host_rsa_key.pub")
	err = res.HostKeyCallback("example.sshfp.xor-gate.org", nil, pubKey)
	assert.Nil(t, err)

	pubKey = testParseAuthorizedKey(t, "ssh_host_ed25519_key.pub")
	err = res.HostKeyCallback("example.sshfp.xor-gate.org", nil, pubKey)
	assert.Nil(t, err)
}
