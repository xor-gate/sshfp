// Copyright 2018 sshfp authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package sshfp

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseZone(t *testing.T) {
	td, err := os.Open("testdata/example.sshfp.xor-gate.org.zone")
	require.Nil(t, err)
	require.NotNil(t, td)
	defer td.Close()

	entries, err := ParseZone(td)
	require.Nil(t, err)
	assert.Len(t, entries, 8)
}

func TestParseHostname(t *testing.T) {
	u, err := ParseHostname("example.com")
	require.Nil(t, err)
	require.NotNil(t, u)
	assert.Equal(t, "ssh", u.Scheme)
	assert.Equal(t, "example.com", u.Hostname())
}
