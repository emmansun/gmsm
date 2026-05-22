// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mldsa

import "testing"

var (
	benchmarkSimpleBitPack4Loong64Sink [encodingSize4]byte
	benchmarkSimpleBitPack6Loong64Sink [encodingSize6]byte
	benchmarkBitPackLoong64Sink        []byte
	benchmarkBitUnpackLoong64Sink      ringElement
)

func TestSimpleBitPack4BitsLASX(t *testing.T) {
	if !useLASX {
		t.Skip("LASX is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()
		for j := range r {
			r[j] &= 0xF
		}

		var got [encodingSize4]byte
		simpleBitPack4BitsLASX(&got[0], &r[0])

		var want [encodingSize4]byte
		simpleBitPack4BitsGeneric(want[:], &r)

		if got != want {
			t.Fatalf("simpleBitPack4BitsLASX mismatch on iteration %d", i)
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

func TestSimpleBitPack4BitsHighBitsGamma32LASX(t *testing.T) {
	if !useLASX {
		t.Skip("LASX is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize4]byte
		simpleBitPack4BitsHighBitsGamma32LASX(&got[0], &r[0])

		var want [encodingSize4]byte
		simpleBitPack4BitsHighBitsGeneric(want[:], &r, gamma2QMinus1Div32)

		if got != want {
			t.Fatalf("simpleBitPack4BitsHighBitsGamma32LASX mismatch on iteration %d", i)
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

func TestSimpleBitPack6BitsLASX(t *testing.T) {
	if !useLASX {
		t.Skip("LASX is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()
		for j := range r {
			r[j] %= 44
		}

		var got [encodingSize6]byte
		simpleBitPack6BitsLASX(&got[0], &r[0])

		var want [encodingSize6]byte
		simpleBitPack6BitsGeneric(want[:], &r)

		if got != want {
			t.Fatalf("simpleBitPack6BitsLASX mismatch on iteration %d", i)
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

func TestSimpleBitPack6BitsHighBitsGamma88LASX(t *testing.T) {
	if !useLASX {
		t.Skip("LASX is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize6]byte
		simpleBitPack6BitsHighBitsGamma88LASX(&got[0], &r[0])

		var want [encodingSize6]byte
		simpleBitPack6BitsHighBitsGeneric(want[:], &r, gamma2QMinus1Div88)

		if got != want {
			t.Fatalf("simpleBitPack6BitsHighBitsGamma88LASX mismatch on iteration %d", i)
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

func TestBitPackSignedTwoPower17LASX(t *testing.T) {
	if !useLASX {
		t.Skip("LASX is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize18]byte
		bitPackSignedTwoPower17LASX(&got[0], &r[0])

		var want [encodingSize18]byte
		bitPackSignedTwoPower17Generic(want[:], &r)

		if got != want {
			t.Fatalf("bitPackSignedTwoPower17LASX mismatch on iteration %d", i)
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

func TestBitPackSignedTwoPower19LASX(t *testing.T) {
	if !useLASX {
		t.Skip("LASX is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var got [encodingSize20]byte
		bitPackSignedTwoPower19LASX(&got[0], &r[0])

		var want [encodingSize20]byte
		bitPackSignedTwoPower19Generic(want[:], &r)

		if got != want {
			t.Fatalf("bitPackSignedTwoPower19LASX mismatch on iteration %d", i)
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

func TestBitUnpackSignedTwoPower17LASX(t *testing.T) {
	if !useLASX {
		t.Skip("LASX is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var packed [encodingSize18]byte
		bitPackSignedTwoPower17Generic(packed[:], &r)

		var got ringElement
		bitUnpackSignedTwoPower17LASX(&packed[0], &got)

		var want ringElement
		bitUnpackSignedTwoPower17Generic(packed[:], &want)

		if got != want {
			t.Fatalf("bitUnpackSignedTwoPower17LASX mismatch on iteration %d", i)
		}
	}
}

func TestBitUnpackSignedTwoPower17(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var packed [encodingSize18]byte
		bitPackSignedTwoPower17Generic(packed[:], &r)

		var got ringElement
		bitUnpackSignedTwoPower17(packed[:], &got)

		var want ringElement
		bitUnpackSignedTwoPower17Generic(packed[:], &want)

		if got != want {
			t.Fatalf("bitUnpackSignedTwoPower17 dispatch mismatch on iteration %d", i)
		}
	}
}

func TestBitUnpackSignedTwoPower19LASX(t *testing.T) {
	if !useLASX {
		t.Skip("LASX is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var packed [encodingSize20]byte
		bitPackSignedTwoPower19Generic(packed[:], &r)

		var got ringElement
		bitUnpackSignedTwoPower19LASX(&packed[0], &got)

		var want ringElement
		bitUnpackSignedTwoPower19Generic(packed[:], &want)

		if got != want {
			t.Fatalf("bitUnpackSignedTwoPower19LASX mismatch on iteration %d", i)
		}
	}
}

func TestBitUnpackSignedTwoPower19(t *testing.T) {
	for i := 0; i < 16; i++ {
		r := randomRingElement()

		var packed [encodingSize20]byte
		bitPackSignedTwoPower19Generic(packed[:], &r)

		var got ringElement
		bitUnpackSignedTwoPower19(packed[:], &got)

		var want ringElement
		bitUnpackSignedTwoPower19Generic(packed[:], &want)

		if got != want {
			t.Fatalf("bitUnpackSignedTwoPower19 dispatch mismatch on iteration %d", i)
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
		benchmarkSimpleBitPack4Loong64Sink = out
	})
	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX is not available")
		}
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsLASX(&out[0], &r[0])
		}
		benchmarkSimpleBitPack4Loong64Sink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			copy(out[:], simpleBitPack4Bits(out[:0], &r))
		}
		benchmarkSimpleBitPack4Loong64Sink = out
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
		benchmarkSimpleBitPack6Loong64Sink = out
	})
	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX is not available")
		}
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsLASX(&out[0], &r[0])
		}
		benchmarkSimpleBitPack6Loong64Sink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			copy(out[:], simpleBitPack6Bits(out[:0], &r))
		}
		benchmarkSimpleBitPack6Loong64Sink = out
	})
}

func BenchmarkBitPackSignedTwoPower17(b *testing.B) {
	r := randomRingElement()
	var out [encodingSize18]byte
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower17Generic(out[:], &r)
		}
		benchmarkBitPackLoong64Sink = out[:]
	})
	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX is not available")
		}
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower17LASX(&out[0], &r[0])
		}
		benchmarkBitPackLoong64Sink = out[:]
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out2 := bitPackSignedTwoPower17(nil, &r)
			_ = out2
		}
	})
}

func BenchmarkBitPackSignedTwoPower19(b *testing.B) {
	r := randomRingElement()
	var out [encodingSize20]byte
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower19Generic(out[:], &r)
		}
		benchmarkBitPackLoong64Sink = out[:]
	})
	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX is not available")
		}
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower19LASX(&out[0], &r[0])
		}
		benchmarkBitPackLoong64Sink = out[:]
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			out2 := bitPackSignedTwoPower19(nil, &r)
			_ = out2
		}
	})
}

func BenchmarkBitUnpackSignedTwoPower17(b *testing.B) {
	r := randomRingElement()
	var packed [encodingSize18]byte
	bitPackSignedTwoPower17Generic(packed[:], &r)
	var out ringElement
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower17Generic(packed[:], &out)
		}
		benchmarkBitUnpackLoong64Sink = out
	})
	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX is not available")
		}
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower17LASX(&packed[0], &out)
		}
		benchmarkBitUnpackLoong64Sink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower17(packed[:], &out)
		}
		benchmarkBitUnpackLoong64Sink = out
	})
}

func BenchmarkBitUnpackSignedTwoPower19(b *testing.B) {
	r := randomRingElement()
	var packed [encodingSize20]byte
	bitPackSignedTwoPower19Generic(packed[:], &r)
	var out ringElement
	b.ReportAllocs()
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower19Generic(packed[:], &out)
		}
		benchmarkBitUnpackLoong64Sink = out
	})
	b.Run("lasx", func(b *testing.B) {
		if !useLASX {
			b.Skip("LASX is not available")
		}
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower19LASX(&packed[0], &out)
		}
		benchmarkBitUnpackLoong64Sink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower19(packed[:], &out)
		}
		benchmarkBitUnpackLoong64Sink = out
	})
}
