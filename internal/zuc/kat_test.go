// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package zuc

import "testing"

func TestKATEEA(t *testing.T) {
	if err := KATEEA(); err != nil {
		t.Fatal(err)
	}
}

func TestKATEIA(t *testing.T) {
	if err := KATEIA(); err != nil {
		t.Fatal(err)
	}
}
