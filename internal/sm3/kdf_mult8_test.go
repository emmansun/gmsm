// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || loong64) && !purego

package sm3

import "testing"

func TestKdfBy8PaddingBlockBoundary(t *testing.T) {
	compareKdfWithGeneric(t, kdfBy8, 8)
}
