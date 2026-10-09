// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import (
	"os"
	"strconv"
	"testing"
)

// TestRVVGeometry is the CI probe target for the riscv64 VLEN matrix. The
// wanted VLEN in bits is provided via DIFF_EXPECT_VLENB; the job fails if
// the requested QEMU vector length property did not take effect.
func TestRVVGeometry(t *testing.T) {
	want, err := strconv.Atoi(os.Getenv("DIFF_EXPECT_VLENB"))
	if err != nil || want == 0 {
		t.Skip("set DIFF_EXPECT_VLENB=<bits> to verify the QEMU vector length")
	}
	ExpectVectorLength(t, want)
}
