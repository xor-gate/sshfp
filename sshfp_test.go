// Copyright 2018 sshfp authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package sshfp

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func testParseZone(t *testing.T, filename string) []*Entry {
	td, err := os.Open(filepath.Join("testdata", filename))
	require.Nil(t, err)
	require.NotNil(t, td)
	defer td.Close()

	entries, err := ParseZone(td)
	require.Nil(t, err)
	return entries
}

func testParseAuthorizedKey(t *testing.T, filename string) ssh.PublicKey {
	key, err := ioutil.ReadFile(filepath.Join("testdata", filename))
	require.Nil(t, err)
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(key)
	require.Nil(t, err)
	return pubKey
}

func TestParseZone(t *testing.T) {
	entries := testParseZone(t, "example.sshfp.xor-gate.org.zone")
	assert.Len(t, entries, 8)
}

func TestParseHostname(t *testing.T) {
	u, err := ParseHostname("example.com")
	require.Nil(t, err)
	require.NotNil(t, u)
	assert.Equal(t, "ssh", u.Scheme)
	assert.Equal(t, "example.com", u.Hostname())
}
