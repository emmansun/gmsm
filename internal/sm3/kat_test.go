// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm3

import "testing"

func TestKATHash(t *testing.T) {
	if err := KATHash(); err != nil {
		t.Fatal(err)
	}
}

func TestKATBlock(t *testing.T) {
	if err := KATBlock(); err != nil {
		t.Fatal(err)
	}
}

func TestKATIncremental(t *testing.T) {
	if err := KATIncremental(); err != nil {
		t.Fatal(err)
	}
}
