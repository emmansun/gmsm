// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import "testing"

func TestKATSignDeterministic(t *testing.T) {
	if err := KATSignDeterministic(); err != nil {
		t.Fatal(err)
	}
}
