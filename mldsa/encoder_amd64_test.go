// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package mldsa

import "testing"

var benchmarkSimpleBitPack4Sink [encodingSize4]byte
var benchmarkSimpleBitPack6Sink [encodingSize6]byte

func TestSimpleBitPack4BitsAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()
		for j := range r {
			r[j] &= 0xF
		}

		var got [encodingSize4]byte
		simpleBitPack4BitsAVX2(&got[0], &r[0])

		var want [encodingSize4]byte
		simpleBitPack4BitsGeneric(want[:], &r)

		if got != want {
			t.Fatalf("simpleBitPack4BitsAVX2 mismatch on iteration %d", i)
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

func TestSimpleBitPack4BitsHighBitsGamma32AVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize4]byte
		simpleBitPack4BitsHighBitsGamma32AVX2(&got[0], &r[0])

		var want [encodingSize4]byte
		simpleBitPack4BitsHighBitsGeneric(want[:], &r, gamma2QMinus1Div32)

		if got != want {
			t.Fatalf("simpleBitPack4BitsHighBitsGamma32AVX2 mismatch on iteration %d", i)
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

func TestSimpleBitPack6BitsAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()
		for j := range r {
			r[j] %= 44
		}

		var got [encodingSize6]byte
		simpleBitPack6BitsAVX2(&got[0], &r[0])

		var want [encodingSize6]byte
		simpleBitPack6BitsGeneric(want[:], &r)

		if got != want {
			t.Fatalf("simpleBitPack6BitsAVX2 mismatch on iteration %d", i)
		}
	}
}

func TestSimpleBitPack6Bits(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()
		for j := range r {
			r[j] %= 44
		}

		got := simpleBitPack6Bits(nil, &r)

		var want [encodingSize6]byte
		simpleBitPack6BitsGeneric(want[:], &r)

		if string(got) != string(want[:]) {
			t.Fatalf("simpleBitPack6Bits dispatch mismatch on iteration %d", i)
		}
	}
}

func TestSimpleBitPack6BitsHighBitsGamma88AVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize6]byte
		simpleBitPack6BitsHighBitsGamma88AVX2(&got[0], &r[0])

		var want [encodingSize6]byte
		simpleBitPack6BitsHighBitsGeneric(want[:], &r, gamma2QMinus1Div88)

		if got != want {
			t.Fatalf("simpleBitPack6BitsHighBitsGamma88AVX2 mismatch on iteration %d", i)
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
		benchmarkSimpleBitPack4Sink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			copy(out[:], simpleBitPack4Bits(out[:0], &r))
		}
		benchmarkSimpleBitPack4Sink = out
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsAVX2(&out[0], &r[0])
		}
		benchmarkSimpleBitPack4Sink = out
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
		benchmarkSimpleBitPack4Sink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsHighBits(out[:], &r, gamma2QMinus1Div32)
		}
		benchmarkSimpleBitPack4Sink = out
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsHighBitsGamma32AVX2(&out[0], &r[0])
		}
		benchmarkSimpleBitPack4Sink = out
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
		benchmarkSimpleBitPack6Sink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			copy(out[:], simpleBitPack6Bits(out[:0], &r))
		}
		benchmarkSimpleBitPack6Sink = out
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsAVX2(&out[0], &r[0])
		}
		benchmarkSimpleBitPack6Sink = out
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
		benchmarkSimpleBitPack6Sink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsHighBits(out[:], &r, gamma2QMinus1Div88)
		}
		benchmarkSimpleBitPack6Sink = out
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsHighBitsGamma88AVX2(&out[0], &r[0])
		}
		benchmarkSimpleBitPack6Sink = out
	})
}

func TestBitPackSignedTwoPower17(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()
		got := bitPackSignedTwoPower17(nil, &r)

		var want [encodingSize18]byte
		bitPackSignedTwoPower17Generic(want[:], &r)

		if string(got) != string(want[:]) {
			t.Fatalf("bitPackSignedTwoPower17 mismatch on iteration %d", i)
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
			t.Fatalf("bitPackSignedTwoPower19 mismatch on iteration %d", i)
		}
	}
}

var benchmarkBitPackSink []byte

func BenchmarkBitPackSignedTwoPower17(b *testing.B) {
	r := randomRingElement()
	out := make([]byte, 0, encodingSize18)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out = bitPackSignedTwoPower17(out[:0], &r)
	}
	benchmarkBitPackSink = out
}

func BenchmarkBitPackSignedTwoPower19(b *testing.B) {
	r := randomRingElement()
	out := make([]byte, 0, encodingSize20)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out = bitPackSignedTwoPower19(out[:0], &r)
	}
	benchmarkBitPackSink = out
}

func TestBitPackSignedTwoPower17AVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize18]byte
		bitPackSignedTwoPower17AVX2(&got[0], &r[0])

		var want [encodingSize18]byte
		bitPackSignedTwoPower17Generic(want[:], &r)

		if got != want {
			t.Fatalf("bitPackSignedTwoPower17AVX2 mismatch on iteration %d", i)
		}
	}
}

func TestBitPackSignedTwoPower19AVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize20]byte
		bitPackSignedTwoPower19AVX2(&got[0], &r[0])

		var want [encodingSize20]byte
		bitPackSignedTwoPower19Generic(want[:], &r)

		if got != want {
			t.Fatalf("bitPackSignedTwoPower19AVX2 mismatch on iteration %d", i)
		}
	}
}

func BenchmarkBitPackSignedTwoPower17AVX2(b *testing.B) {
	if !useAVX2 {
		b.Skip("AVX2 is not available")
	}
	r := randomRingElement()
	var out [encodingSize18]byte

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower17Generic(out[:], &r)
		}
		benchmarkBitPackSink = out[:]
	})

	b.Run("avx2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower17AVX2(&out[0], &r[0])
		}
		benchmarkBitPackSink = out[:]
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out2 := bitPackSignedTwoPower17(nil, &r)
			_ = out2
		}
	})
}

func BenchmarkBitPackSignedTwoPower19AVX2(b *testing.B) {
	if !useAVX2 {
		b.Skip("AVX2 is not available")
	}
	r := randomRingElement()
	var out [encodingSize20]byte

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower19Generic(out[:], &r)
		}
		benchmarkBitPackSink = out[:]
	})

	b.Run("avx2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower19AVX2(&out[0], &r[0])
		}
		benchmarkBitPackSink = out[:]
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out2 := bitPackSignedTwoPower19(nil, &r)
			_ = out2
		}
	})
}

func TestBitUnpackSignedTwoPower17AVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()
		// encode first, then decode
		packed := bitPackSignedTwoPower17Generic_(r)

		var got ringElement
		bitUnpackSignedTwoPower17AVX2(&packed[0], &got)

		var want ringElement
		bitUnpackSignedTwoPower17Generic(packed[:], &want)

		if got != want {
			t.Fatalf("bitUnpackSignedTwoPower17AVX2 mismatch on iteration %d", i)
		}
	}
}

func TestBitUnpackSignedTwoPower19AVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()
		packed := bitPackSignedTwoPower19Generic_(r)

		var got ringElement
		bitUnpackSignedTwoPower19AVX2(&packed[0], &got)

		var want ringElement
		bitUnpackSignedTwoPower19Generic(packed[:], &want)

		if got != want {
			t.Fatalf("bitUnpackSignedTwoPower19AVX2 mismatch on iteration %d", i)
		}
	}
}

func TestBitUnpackSignedTwoPower17(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()
		packed := bitPackSignedTwoPower17Generic_(r)

		var got, want ringElement
		bitUnpackSignedTwoPower17(packed[:], &got)
		bitUnpackSignedTwoPower17Generic(packed[:], &want)

		if got != want {
			t.Fatalf("bitUnpackSignedTwoPower17 dispatch mismatch on iteration %d", i)
		}
	}
}

func TestBitUnpackSignedTwoPower19(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()
		packed := bitPackSignedTwoPower19Generic_(r)

		var got, want ringElement
		bitUnpackSignedTwoPower19(packed[:], &got)
		bitUnpackSignedTwoPower19Generic(packed[:], &want)

		if got != want {
			t.Fatalf("bitUnpackSignedTwoPower19 dispatch mismatch on iteration %d", i)
		}
	}
}

// helpers: pack via generic so the unpack tests don't depend on pack correctness
func bitPackSignedTwoPower17Generic_(f ringElement) [encodingSize18]byte {
	var buf [encodingSize18]byte
	bitPackSignedTwoPower17Generic(buf[:], &f)
	return buf
}

func bitPackSignedTwoPower19Generic_(f ringElement) [encodingSize20]byte {
	var buf [encodingSize20]byte
	bitPackSignedTwoPower19Generic(buf[:], &f)
	return buf
}

var benchmarkBitUnpackSink ringElement

func BenchmarkBitUnpackSignedTwoPower17AVX2(b *testing.B) {
	r := randomRingElement()
	packed := bitPackSignedTwoPower17Generic_(r)
	var out ringElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower17Generic(packed[:], &out)
		}
		benchmarkBitUnpackSink = out
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower17AVX2(&packed[0], &out)
		}
		benchmarkBitUnpackSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower17(packed[:], &out)
		}
		benchmarkBitUnpackSink = out
	})
}

func BenchmarkBitUnpackSignedTwoPower19AVX2(b *testing.B) {
	r := randomRingElement()
	packed := bitPackSignedTwoPower19Generic_(r)
	var out ringElement

	b.ReportAllocs()

	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower19Generic(packed[:], &out)
		}
		benchmarkBitUnpackSink = out
	})

	b.Run("avx2", func(b *testing.B) {
		if !useAVX2 {
			b.Skip("AVX2 is not available")
		}
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower19AVX2(&packed[0], &out)
		}
		benchmarkBitUnpackSink = out
	})

	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower19(packed[:], &out)
		}
		benchmarkBitUnpackSink = out
	})
}
