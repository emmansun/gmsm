// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package sm4

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
)

func TestGHASHMulLoong(t *testing.T) {
	knownX, _ := hex.DecodeString("0388dace60b6a392f328c2b971b2fe78")
	knownH, _ := hex.DecodeString("66e94bd4ef8a2c3b884cfa59ca342b2e")
	want, _ := hex.DecodeString("5e2ec746917062882c85b0685353deb7")
	var x, h, got [16]byte
	copy(x[:], knownX)
	copy(h[:], knownH)
	ghashMulLoong(&got, &x, &h)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("known vector: got %x, want %x", got, want)
	}

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 256; i++ {
		if _, err := rng.Read(x[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rng.Read(h[:]); err != nil {
			t.Fatal(err)
		}
		ghashMulLoong(&got, &x, &h)
		want := ghashMulReference(x, h)
		if !bytes.Equal(got[:], want[:]) {
			t.Fatalf("case %d: got %x, want %x", i, got, want)
		}
	}
}

func BenchmarkGHASHMulLoong(b *testing.B) {
	x := [16]byte{0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78}
	h := [16]byte{0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e}
	var out [16]byte
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ghashMulLoong(&out, &x, &h)
	}
}

func BenchmarkGHASHMulReference(b *testing.B) {
	x := [16]byte{0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78}
	h := [16]byte{0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e}
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ghashMulReference(x, h)
	}
}

func ghashMulReference(x, h [16]byte) (z [16]byte) {
	v := h
	for i := 0; i < 128; i++ {
		bit := (x[i/8] >> (7 - uint(i&7))) & 1
		mask := byte(0) - bit
		for j := range z {
			z[j] ^= v[j] & mask
		}
		lsb := v[15] & 1
		for j := len(v) - 1; j > 0; j-- {
			v[j] = v[j]>>1 | v[j-1]<<7
		}
		v[0] >>= 1
		v[0] ^= 0xe1 & (byte(0) - lsb)
	}
	return z
}
