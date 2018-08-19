// Copyright 2018 sshfp authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package sshfp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryCache(t *testing.T) {
	c, err := NewMemoryCache(16)
	require.Nil(t, err)
	require.NotNil(t, c)
	entry := &Entry{}
	assert.Nil(t, c.Add(entry))
	assert.Nil(t, c.Remove(entry))
}
