// Copyright 2018 sshfp authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package sshfp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntry(t *testing.T) {
	e := &Entry{}
	assert.True(t, e.IsValid())
}
