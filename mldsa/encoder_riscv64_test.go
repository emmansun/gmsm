// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && go1.26 && !purego

package mldsa

import (
	"math/rand/v2"
	"testing"
)

func requireRVVEncoder(t *testing.T) {
	t.Helper()
	if !hasRVV {
		t.Skip("RVV is not available")
	}
}

func randomPackableRingElement(r int32, bits uint) ringElement {
	var f ringElement
	mask := uint32((1 << bits) - 1)

	for i := range f {
		t := fieldElement(rand.Uint32() & mask)
		f[i] = fieldSub(fieldElement(r), t)
	}

	return f
}

func TestSimpleBitPack4BitsRVV(t *testing.T) {
	requireRVVEncoder(t)
	for iteration := 0; iteration < 16; iteration++ {
		input := randomRingElement()
		for i := range input {
			input[i] &= 15
		}
		input[0], input[1] = 0, 15

		var got, want [encodingSize4]byte
		simpleBitPack4BitsRVV(&got[0], &input[0])
		simpleBitPack4BitsGeneric(want[:], &input)
		if got != want {
			t.Fatalf("simpleBitPack4BitsRVV mismatch on iteration %d", iteration)
		}
	}
}

func TestSimpleBitPack6BitsRVV(t *testing.T) {
	requireRVVEncoder(t)
	for iteration := 0; iteration < 16; iteration++ {
		input := randomRingElement()
		for i := range input {
			input[i] %= 44
		}
		input[0], input[1], input[2], input[3] = 0, 1, 42, 43

		var got, want [encodingSize6]byte
		simpleBitPack6BitsRVV(&got[0], &input[0])
		simpleBitPack6BitsGeneric(want[:], &input)
		if got != want {
			t.Fatalf("simpleBitPack6BitsRVV mismatch on iteration %d", iteration)
		}
	}
}

func TestSimpleBitPackHighBitsRVV(t *testing.T) {
	requireRVVEncoder(t)
	for iteration := 0; iteration < 16; iteration++ {
		input := randomRingElement()
		input[0], input[1], input[2], input[3] = 0, 127, qMinus1Div2, q-1

		var got4, want4 [encodingSize4]byte
		simpleBitPack4BitsHighBitsGamma32RVV(&got4[0], &input[0])
		simpleBitPack4BitsHighBitsGeneric(want4[:], &input, gamma2QMinus1Div32)
		if got4 != want4 {
			t.Fatalf("simpleBitPack4BitsHighBitsGamma32RVV mismatch on iteration %d", iteration)
		}

		var got6, want6 [encodingSize6]byte
		simpleBitPack6BitsHighBitsGamma88RVV(&got6[0], &input[0])
		simpleBitPack6BitsHighBitsGeneric(want6[:], &input, gamma2QMinus1Div88)
		if got6 != want6 {
			t.Fatalf("simpleBitPack6BitsHighBitsGamma88RVV mismatch on iteration %d", iteration)
		}
	}
}

func TestSimpleBitPackDispatchRVV(t *testing.T) {
	input4 := randomRingElement()
	input6 := input4
	for i := range input4 {
		input4[i] &= 15
		input6[i] %= 44
	}

	got4 := simpleBitPack4Bits([]byte{1, 2, 3}, &input4)
	var want4 [encodingSize4]byte
	simpleBitPack4BitsGeneric(want4[:], &input4)
	if len(got4) != 3+encodingSize4 || string(got4[:3]) != string([]byte{1, 2, 3}) || string(got4[3:]) != string(want4[:]) {
		t.Fatal("simpleBitPack4Bits dispatch did not preserve append semantics")
	}

	got6 := simpleBitPack6Bits(nil, &input6)
	var want6 [encodingSize6]byte
	simpleBitPack6BitsGeneric(want6[:], &input6)
	if string(got6) != string(want6[:]) {
		t.Fatal("simpleBitPack6Bits dispatch mismatch")
	}

	var gotHigh4, wantHigh4 [encodingSize4]byte
	simpleBitPack4BitsHighBits(gotHigh4[:], &input4, gamma2QMinus1Div88)
	simpleBitPack4BitsHighBitsGeneric(wantHigh4[:], &input4, gamma2QMinus1Div88)
	if gotHigh4 != wantHigh4 {
		t.Fatal("simpleBitPack4BitsHighBits fallback mismatch")
	}

	var gotHigh6, wantHigh6 [encodingSize6]byte
	simpleBitPack6BitsHighBits(gotHigh6[:], &input6, gamma2QMinus1Div32)
	simpleBitPack6BitsHighBitsGeneric(wantHigh6[:], &input6, gamma2QMinus1Div32)
	if gotHigh6 != wantHigh6 {
		t.Fatal("simpleBitPack6BitsHighBits fallback mismatch")
	}
}

func TestBitPackSignedRVV(t *testing.T) {
	requireRVVEncoder(t)
	for iteration := 0; iteration < 16; iteration++ {
		input := randomPackableRingElement(1<<17, 18)

		var got17, want17 [encodingSize18]byte
		bitPackSignedTwoPower17RVV(&got17[0], &input[0])
		bitPackSignedTwoPower17Generic(want17[:], &input)
		if got17 != want17 {
			t.Fatalf("bitPackSignedTwoPower17RVV mismatch on iteration %d", iteration)
		}

		var got19, want19 [encodingSize20]byte
		input = randomPackableRingElement(1<<19, 20)
		bitPackSignedTwoPower19RVV(&got19[0], &input[0])
		bitPackSignedTwoPower19Generic(want19[:], &input)
		if got19 != want19 {
			//t.Fatalf("bitPackSignedTwoPower19RVV mismatch on iteration %d", iteration)
			for i := range want19 {
				if got19[i] != want19[i] {
					pair := i / 5
					byteInPair := i % 5
					t0Index := pair * 2
					t1Index := t0Index + 1

					t.Fatalf(
						"bitPackSignedTwoPower19RVV mismatch:"+
							" byte=%d pair=%d byteInPair=%d"+
							" f[%d]=%d f[%d]=%d"+
							" got=%02x want=%02x"+
							" gotPair=% x wantPair=% x",
						i, pair, byteInPair,
						t0Index, input[t0Index],
						t1Index, input[t1Index],
						got19[i], want19[i],
						got19[pair*5:pair*5+5],
						want19[pair*5:pair*5+5],
					)
				}
			}
		}
	}
}

func TestBitUnpackSignedRVV(t *testing.T) {
	requireRVVEncoder(t)
	for iteration := 0; iteration < 16; iteration++ {
		input := randomPackableRingElement(1<<19, 20)

		var packed17 [encodingSize18]byte
		bitPackSignedTwoPower17Generic(packed17[:], &input)
		var got17, want17 ringElement
		bitUnpackSignedTwoPower17RVV(&packed17[0], &got17)
		bitUnpackSignedTwoPower17Generic(packed17[:], &want17)
		if got17 != want17 {
			t.Fatalf("bitUnpackSignedTwoPower17RVV mismatch on iteration %d", iteration)
		}

		var packed19 [encodingSize20]byte
		input = randomPackableRingElement(1<<19, 20)
		bitPackSignedTwoPower19Generic(packed19[:], &input)
		var got19, want19 ringElement
		bitUnpackSignedTwoPower19RVV(&packed19[0], &got19)
		bitUnpackSignedTwoPower19Generic(packed19[:], &want19)
		if got19 != want19 {
			t.Fatalf("bitUnpackSignedTwoPower19RVV mismatch on iteration %d", iteration)
		}
	}
}

func TestBitPackSignedDispatchRVV(t *testing.T) {
	input := randomPackableRingElement(1<<19, 20)

	got17 := bitPackSignedTwoPower17(nil, &input)
	var want17 [encodingSize18]byte
	bitPackSignedTwoPower17Generic(want17[:], &input)
	if string(got17) != string(want17[:]) {
		t.Fatal("bitPackSignedTwoPower17 dispatch mismatch")
	}
	var unpacked17, expected17 ringElement
	bitUnpackSignedTwoPower17(got17, &unpacked17)
	bitUnpackSignedTwoPower17Generic(want17[:], &expected17)
	if unpacked17 != expected17 {
		t.Fatal("bitUnpackSignedTwoPower17 dispatch mismatch")
	}

	input = randomPackableRingElement(1<<19, 20)
	got19 := bitPackSignedTwoPower19(nil, &input)
	var want19 [encodingSize20]byte
	bitPackSignedTwoPower19Generic(want19[:], &input)
	if string(got19) != string(want19[:]) {
		t.Fatal("bitPackSignedTwoPower19 dispatch mismatch")
	}
	var unpacked19, expected19 ringElement
	bitUnpackSignedTwoPower19(got19, &unpacked19)
	bitUnpackSignedTwoPower19Generic(want19[:], &expected19)
	if unpacked19 != expected19 {
		t.Fatal("bitUnpackSignedTwoPower19 dispatch mismatch")
	}
}

var benchmarkEncoderBytesRVVSink []byte
var benchmarkEncoderRingRVVSink ringElement

func requireRVVEncoderBenchmark(b *testing.B) {
	b.Helper()
	if !hasRVV {
		b.Skip("RVV is not available")
	}
}

func BenchmarkSimpleBitPack4BitsRVV(b *testing.B) {
	input := randomRingElement()
	for i := range input {
		input[i] &= 15
	}
	var out [encodingSize4]byte
	b.ReportAllocs()
	b.SetBytes(encodingSize4)
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsGeneric(out[:], &input)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = simpleBitPack4Bits(out[:0], &input)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("rvv", func(b *testing.B) {
		requireRVVEncoderBenchmark(b)
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsRVV(&out[0], &input[0])
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
}

func BenchmarkSimpleBitPack4BitsHighBitsRVV(b *testing.B) {
	input := randomRingElement()
	var out [encodingSize4]byte
	b.ReportAllocs()
	b.SetBytes(encodingSize4)
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsHighBitsGeneric(out[:], &input, gamma2QMinus1Div32)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsHighBits(out[:], &input, gamma2QMinus1Div32)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("rvv", func(b *testing.B) {
		requireRVVEncoderBenchmark(b)
		for i := 0; i < b.N; i++ {
			simpleBitPack4BitsHighBitsGamma32RVV(&out[0], &input[0])
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
}

func BenchmarkSimpleBitPack6BitsRVV(b *testing.B) {
	input := randomRingElement()
	for i := range input {
		input[i] %= 44
	}
	var out [encodingSize6]byte
	b.ReportAllocs()
	b.SetBytes(encodingSize6)
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsGeneric(out[:], &input)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = simpleBitPack6Bits(out[:0], &input)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("rvv", func(b *testing.B) {
		requireRVVEncoderBenchmark(b)
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsRVV(&out[0], &input[0])
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
}

func BenchmarkSimpleBitPack6BitsHighBitsRVV(b *testing.B) {
	input := randomRingElement()
	var out [encodingSize6]byte
	b.ReportAllocs()
	b.SetBytes(encodingSize6)
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsHighBitsGeneric(out[:], &input, gamma2QMinus1Div88)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsHighBits(out[:], &input, gamma2QMinus1Div88)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("rvv", func(b *testing.B) {
		requireRVVEncoderBenchmark(b)
		for i := 0; i < b.N; i++ {
			simpleBitPack6BitsHighBitsGamma88RVV(&out[0], &input[0])
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
}

func BenchmarkBitPackSignedTwoPower17RVV(b *testing.B) {
	input := randomPackableRingElement(1<<17, 18)
	var out [encodingSize18]byte
	b.ReportAllocs()
	b.SetBytes(encodingSize18)
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower17Generic(out[:], &input)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bitPackSignedTwoPower17(out[:0], &input)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("rvv", func(b *testing.B) {
		requireRVVEncoderBenchmark(b)
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower17RVV(&out[0], &input[0])
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
}

func BenchmarkBitPackSignedTwoPower19RVV(b *testing.B) {
	input := randomPackableRingElement(1<<19, 20)
	var out [encodingSize20]byte
	b.ReportAllocs()
	b.SetBytes(encodingSize20)
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower19Generic(out[:], &input)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = bitPackSignedTwoPower19(out[:0], &input)
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
	b.Run("rvv", func(b *testing.B) {
		requireRVVEncoderBenchmark(b)
		for i := 0; i < b.N; i++ {
			bitPackSignedTwoPower19RVV(&out[0], &input[0])
		}
		benchmarkEncoderBytesRVVSink = out[:]
	})
}

func BenchmarkBitUnpackSignedTwoPower17RVV(b *testing.B) {
	input := randomPackableRingElement(1<<17, 18)
	var packed [encodingSize18]byte
	bitPackSignedTwoPower17Generic(packed[:], &input)
	var out ringElement
	b.ReportAllocs()
	b.SetBytes(encodingSize18)
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower17Generic(packed[:], &out)
		}
		benchmarkEncoderRingRVVSink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower17(packed[:], &out)
		}
		benchmarkEncoderRingRVVSink = out
	})
	b.Run("rvv", func(b *testing.B) {
		requireRVVEncoderBenchmark(b)
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower17RVV(&packed[0], &out)
		}
		benchmarkEncoderRingRVVSink = out
	})
}

func BenchmarkBitUnpackSignedTwoPower19RVV(b *testing.B) {
	input := randomPackableRingElement(1<<19, 20)
	var packed [encodingSize20]byte
	bitPackSignedTwoPower19Generic(packed[:], &input)
	var out ringElement
	b.ReportAllocs()
	b.SetBytes(encodingSize20)
	b.Run("generic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower19Generic(packed[:], &out)
		}
		benchmarkEncoderRingRVVSink = out
	})
	b.Run("dispatch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower19(packed[:], &out)
		}
		benchmarkEncoderRingRVVSink = out
	})
	b.Run("rvv", func(b *testing.B) {
		requireRVVEncoderBenchmark(b)
		for i := 0; i < b.N; i++ {
			bitUnpackSignedTwoPower19RVV(&packed[0], &out)
		}
		benchmarkEncoderRingRVVSink = out
	})
}
