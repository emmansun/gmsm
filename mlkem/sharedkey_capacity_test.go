// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package mlkem

import (
	"crypto/rand"
	"testing"
)

// TestSharedKeyCapacity ensures that both the encapsulated and decapsulated
// shared keys have exactly SharedKeySize capacity, so that the remaining
// secret randomness in the underlying SHA3 output buffer cannot be reached
// by reslicing the returned key.
//
// See https://github.com/golang/go/commit/06fcd67cc3371f8b5c8b577a650afd123ab9dad4.
func TestSharedKeyCapacity(t *testing.T) {
	check := func(t *testing.T, K []byte) {
		t.Helper()
		if len(K) != SharedKeySize || cap(K) != SharedKeySize {
			t.Errorf("len, cap = %d, %d; want %d, %d", len(K), cap(K), SharedKeySize, SharedKeySize)
		}
	}
	t.Run("512", func(t *testing.T) {
		dk, err := GenerateKey512(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		Ke, c, err := dk.EncapsulationKey().Encapsulate(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		Kd, err := dk.Decapsulate(c)
		if err != nil {
			t.Fatal(err)
		}
		Kt, _ := dk.EncapsulationKey().EncapsulateInternal(&[32]byte{})
		check(t, Ke)
		check(t, Kd)
		check(t, Kt)
	})
	t.Run("768", func(t *testing.T) {
		dk, err := GenerateKey768(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		Ke, c, err := dk.EncapsulationKey().Encapsulate(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		Kd, err := dk.Decapsulate(c)
		if err != nil {
			t.Fatal(err)
		}
		Kt, _ := dk.EncapsulationKey().EncapsulateInternal(&[32]byte{})
		check(t, Ke)
		check(t, Kd)
		check(t, Kt)
	})
	t.Run("1024", func(t *testing.T) {
		dk, err := GenerateKey1024(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		Ke, c, err := dk.EncapsulationKey().Encapsulate(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		Kd, err := dk.Decapsulate(c)
		if err != nil {
			t.Fatal(err)
		}
		Kt, _ := dk.EncapsulationKey().EncapsulateInternal(&[32]byte{})
		check(t, Ke)
		check(t, Kd)
		check(t, Kt)
	})
}
