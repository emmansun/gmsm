// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mldsa

import "testing"

func TestSimpleBitPack4BitsNEON(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()
		for j := range r {
			r[j] &= 0xF
		}

		var got [encodingSize4]byte
		simpleBitPack4BitsNEON(&got[0], &r[0])

		var want [encodingSize4]byte
		simpleBitPack4BitsGeneric(want[:], &r)

		if got != want {
			t.Fatalf("simpleBitPack4BitsNEON mismatch on iteration %d", i)
		}
	}
}

func TestSimpleBitPack4Bits(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()
		for j := range r {
			r[j] &= 0xF
		}

		got := simpleBitPack4Bits(nil, &r)

		var want [encodingSize4]byte
		simpleBitPack4BitsGeneric(want[:], &r)

		if string(got) != string(want[:]) {
			t.Fatalf("simpleBitPack4Bits dispatch mismatch on iteration %d", i)
		}
	}
}

func TestSimpleBitPack4BitsHighBitsGamma32NEON(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize4]byte
		simpleBitPack4BitsHighBitsGamma32NEON(&got[0], &r[0])

		var want [encodingSize4]byte
		simpleBitPack4BitsHighBitsGeneric(want[:], &r, gamma2QMinus1Div32)

		if got != want {
			t.Fatalf("simpleBitPack4BitsHighBitsGamma32NEON mismatch on iteration %d", i)
		}
	}
}

func TestSimpleBitPack4BitsHighBits(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		for _, gamma2 := range []uint32{gamma2QMinus1Div32, gamma2QMinus1Div88} {
			var got [encodingSize4]byte
			simpleBitPack4BitsHighBits(got[:], &r, gamma2)

			var want [encodingSize4]byte
			simpleBitPack4BitsHighBitsGeneric(want[:], &r, gamma2)

			if got != want {
				t.Fatalf("simpleBitPack4BitsHighBits mismatch on iteration %d gamma2=%d", i, gamma2)
			}
		}
	}
}

func TestSimpleBitPack6BitsNEON(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()
		for j := range r {
			r[j] %= 44
		}

		var got [encodingSize6]byte
		simpleBitPack6BitsNEON(&got[0], &r[0])

		var want [encodingSize6]byte
		simpleBitPack6BitsGeneric(want[:], &r)

		if got != want {
			t.Fatalf("simpleBitPack6BitsNEON mismatch on iteration %d", i)
		}
	}
}

func TestSimpleBitPack6BitsHighBitsGamma88NEON(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize6]byte
		simpleBitPack6BitsHighBitsGamma88NEON(&got[0], &r[0])

		var want [encodingSize6]byte
		simpleBitPack6BitsHighBitsGeneric(want[:], &r, gamma2QMinus1Div88)

		if got != want {
			t.Fatalf("simpleBitPack6BitsHighBitsGamma88NEON mismatch on iteration %d", i)
		}
	}
}

func TestSimpleBitPack6BitsHighBits(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		for _, gamma2 := range []uint32{gamma2QMinus1Div32, gamma2QMinus1Div88} {
			var got [encodingSize6]byte
			simpleBitPack6BitsHighBits(got[:], &r, gamma2)

			var want [encodingSize6]byte
			simpleBitPack6BitsHighBitsGeneric(want[:], &r, gamma2)

			if got != want {
				t.Fatalf("simpleBitPack6BitsHighBits mismatch on iteration %d gamma2=%d", i, gamma2)
			}
		}
	}
}

func TestBitPackSignedTwoPower17NEON(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize18]byte
		bitPackSignedTwoPower17NEON(&got[0], &r[0])

		var want [encodingSize18]byte
		bitPackSignedTwoPower17Generic(want[:], &r)

		if got != want {
			t.Fatalf("bitPackSignedTwoPower17NEON mismatch on iteration %d", i)
		}
	}
}

func TestBitPackSignedTwoPower17(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		got := bitPackSignedTwoPower17(nil, &r)

		var want [encodingSize18]byte
		bitPackSignedTwoPower17Generic(want[:], &r)

		if string(got) != string(want[:]) {
			t.Fatalf("bitPackSignedTwoPower17 dispatch mismatch on iteration %d", i)
		}
	}
}

func TestBitPackSignedTwoPower19NEON(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize20]byte
		bitPackSignedTwoPower19NEON(&got[0], &r[0])

		var want [encodingSize20]byte
		bitPackSignedTwoPower19Generic(want[:], &r)

		if got != want {
			t.Fatalf("bitPackSignedTwoPower19NEON mismatch on iteration %d", i)
		}
	}
}

func TestBitPackSignedTwoPower19(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		got := bitPackSignedTwoPower19(nil, &r)

		var want [encodingSize20]byte
		bitPackSignedTwoPower19Generic(want[:], &r)

		if string(got) != string(want[:]) {
			t.Fatalf("bitPackSignedTwoPower19 dispatch mismatch on iteration %d", i)
		}
	}
}

var (
	benchmarkSimpleBitPack4Arm64Sink [encodingSize4]byte
	benchmarkSimpleBitPack6Arm64Sink [encodingSize6]byte
	benchmarkBitPackArm64Sink        []byte
)

func BenchmarkSimpleBitPack4Bits(b *testing.B) {
	r := randomRingElement()
	for i := range r {
		r[i] &= 0xF
	}
	var out [encodingSize4]byte
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsGeneric(out[:], &r)
		}
		benchmarkSimpleBitPack4Arm64Sink = out
	})
	b.Run("neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsNEON(&out[0], &r[0])
		}
		benchmarkSimpleBitPack4Arm64Sink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			copy(out[:], simpleBitPack4Bits(out[:0], &r))
		}
		benchmarkSimpleBitPack4Arm64Sink = out
	})
}

func BenchmarkSimpleBitPack4BitsHighBitsGamma32(b *testing.B) {
	r := randomRingElement()
	var out [encodingSize4]byte
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsHighBitsGeneric(out[:], &r, gamma2QMinus1Div32)
		}
		benchmarkSimpleBitPack4Arm64Sink = out
	})
	b.Run("neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsHighBitsGamma32NEON(&out[0], &r[0])
		}
		benchmarkSimpleBitPack4Arm64Sink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsHighBits(out[:], &r, gamma2QMinus1Div32)
		}
		benchmarkSimpleBitPack4Arm64Sink = out
	})
}

func BenchmarkSimpleBitPack6Bits(b *testing.B) {
	r := randomRingElement()
	for i := range r {
		r[i] %= 44
	}
	var out [encodingSize6]byte
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsGeneric(out[:], &r)
		}
		benchmarkSimpleBitPack6Arm64Sink = out
	})
	b.Run("neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsNEON(&out[0], &r[0])
		}
		benchmarkSimpleBitPack6Arm64Sink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			copy(out[:], simpleBitPack6Bits(out[:0], &r))
		}
		benchmarkSimpleBitPack6Arm64Sink = out
	})
}

func BenchmarkSimpleBitPack6BitsHighBitsGamma88(b *testing.B) {
	r := randomRingElement()
	var out [encodingSize6]byte
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsHighBitsGeneric(out[:], &r, gamma2QMinus1Div88)
		}
		benchmarkSimpleBitPack6Arm64Sink = out
	})
	b.Run("neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsHighBitsGamma88NEON(&out[0], &r[0])
		}
		benchmarkSimpleBitPack6Arm64Sink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsHighBits(out[:], &r, gamma2QMinus1Div88)
		}
		benchmarkSimpleBitPack6Arm64Sink = out
	})
}

func BenchmarkBitPackSignedTwoPower17(b *testing.B) {
	r := randomRingElement()
	out := make([]byte, 0, encodingSize18)
	var outFix [encodingSize18]byte
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower17Generic(outFix[:], &r)
		}
	})
	b.Run("neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower17NEON(&outFix[0], &r[0])
		}
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = bitPackSignedTwoPower17(out[:0], &r)
		}
		benchmarkBitPackArm64Sink = out
	})
}

func BenchmarkBitPackSignedTwoPower19(b *testing.B) {
	r := randomRingElement()
	out := make([]byte, 0, encodingSize20)
	var outFix [encodingSize20]byte
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower19Generic(outFix[:], &r)
		}
	})
	b.Run("neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower19NEON(&outFix[0], &r[0])
		}
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out = bitPackSignedTwoPower19(out[:0], &r)
		}
		benchmarkBitPackArm64Sink = out
	})
}
