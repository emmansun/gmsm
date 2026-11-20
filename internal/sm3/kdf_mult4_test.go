// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64 || s390x || ppc64 || ppc64le || loong64) && !purego

package sm3

import (
	"bytes"
	"strconv"
	"testing"
)

func TestKdfBy4PaddingBlockBoundary(t *testing.T) {
	compareKdfWithGeneric(t, kdfBy4, 4)
}

func compareKdfWithGeneric(t *testing.T, kdfFunc func(*digest, int, int) []byte, limit int) {
	t.Helper()
	for tail := 60; tail <= 63; tail++ {
		t.Run("tail_"+strconv.Itoa(tail), func(t *testing.T) {
			z := make([]byte, 2*chunk+tail)
			for i := range z {
				z[i] = byte(i)
			}
			baseMD := new(digest)
			baseMD.Reset()
			baseMD.Write(z)

			keyLen := limit * Size
			got := kdfFunc(baseMD, keyLen, limit)
			want := kdfGeneric(baseMD, keyLen, limit)
			if !bytes.Equal(got, want) {
				t.Fatalf("parallel KDF differs from generic for len(Z) %% 64 = %d", tail)
			}
		})
	}
}
