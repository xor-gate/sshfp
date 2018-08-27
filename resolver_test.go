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

	mc, err := NewMemoryCache(8)
	require.Nil(t, err)
	require.Nil(t, mc.Add(entries...))

	res, err := NewResolver(WithCache(mc))
	require.Nil(t, err)
	require.NotNil(t, res)

	// TODO because we only store just one key and we know the zonefile has last entry Algo 4 2 (ed25519 sha256) the rsa pubkey will return ErrHostKeyChanged
	pubKey := testParseAuthorizedKey(t, "ssh_host_rsa_key.pub")
	assert.Equal(t, ErrHostKeyChanged, res.HostKeyCallback("example.sshfp.xor-gate.org", nil, pubKey))

	pubKey = testParseAuthorizedKey(t, "ssh_host_ed25519_key.pub")
	assert.Nil(t, res.HostKeyCallback("example.sshfp.xor-gate.org", nil, pubKey))
}
