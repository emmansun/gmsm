// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm9_test

import (
	"testing"

	"github.com/emmansun/gmsm/sm9"
)

func TestSelfTest(t *testing.T) {
	if err := sm9.SelfTest(); err != nil {
		t.Fatal(err)
	}
}
