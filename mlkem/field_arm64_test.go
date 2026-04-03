// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mlkem

import (
	"crypto/sha3"
	"testing"
)

func TestNEONForwardNTTMatchesMontgomery(t *testing.T) {
	for i := 0; i < 200; i++ {
		in := randomRingElement()
		got := in
		want := in

		internalNTTNEON(&got)
		internalMontNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: forward NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestNEONInverseNTTMatchesMontgomery(t *testing.T) {
	for i := 0; i < 200; i++ {
		in := randomRingElement()
		internalMontNTT(&in)

		got := nttElement(in)
		want := nttElement(in)

		internalInverseNTTNEON(&got)
		internalMontInverseNTT(&want)

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: inverse NTT mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestNEONDispatchNTTRoundTrip(t *testing.T) {
	for i := 0; i < 100; i++ {
		in := randomRingElement()

		got := in
		internalNTT(&got)
		internalInverseNTT((*nttElement)(&got))

		want := in
		internalMontNTT(&want)
		internalMontInverseNTT((*nttElement)(&want))

		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("iter=%d idx=%d: dispatch round-trip mismatch: got=%d want=%d", i, j, got[j], want[j])
			}
		}
	}
}

func TestNEONNTTMulAccMatchesMontgomery(t *testing.T) {
	for i := 0; i < 100; i++ {
		lhs := randomRingElement()
		rhs := randomRingElement()
		accNEON := randomRingElement()
		accRef := accNEON

		internalMontNTT(&lhs)
		internalMontNTT(&rhs)
		internalMontNTT(&accNEON)
		internalMontNTT(&accRef)

		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		naccNEON := nttElement(accNEON)
		naccRef := nttElement(accRef)

		internalNTTMulAccNEON(&naccNEON, &nlhs, &nrhs)
		nttMontMulAcc(&naccRef, &nlhs, &nrhs)

		for j := range naccNEON {
			if naccNEON[j] != naccRef[j] {
				t.Fatalf("iter=%d idx=%d: NTTMulAcc mismatch: got=%d want=%d", i, j, naccNEON[j], naccRef[j])
			}
		}
	}
}

// TestInternalNTTMulAccNEONOnly isolates the mul-acc NEON path so it can be
// debugged independently from forward/inverse NTT assembly behavior.
func TestInternalNTTMulAccNEONOnly(t *testing.T) {
	for i := 0; i < 200; i++ {
		// Construct direct NTT-domain operands so this test depends only on
		// internalNTTMulAccNEON and the reference nttMontMulAcc implementation.
		nlhs := nttElement(randomRingElement())
		nrhs := nttElement(randomRingElement())
		naccNEON := nttElement(randomRingElement())
		naccInit := naccNEON
		naccRef := naccNEON

		internalNTTMulAccNEON(&naccNEON, &nlhs, &nrhs)
		nttMontMulAcc(&naccRef, &nlhs, &nrhs)

		for j := range naccNEON {
			if naccNEON[j] != naccRef[j] {
				pair := j &^ 1
				a0, a1 := nlhs[pair], nlhs[pair+1]
				b0, b1 := nrhs[pair], nrhs[pair+1]
				accInit0, accInit1 := naccInit[pair], naccInit[pair+1]
				acc0, acc1 := naccRef[pair], naccRef[pair+1]

				ab00 := fieldMontMul(a0, b0)
				ab11 := fieldMontMul(a1, b1)
				ab01 := fieldMontMul(a0, b1)
				ab10 := fieldMontMul(a1, b0)
				evenDelta := fieldAdd(ab00, fieldMontMul(ab11, gammasMontgomery[pair/2]))
				oddDelta := fieldAdd(ab01, ab10)

				neonDeltaEvenRaw := uint16(naccNEON[pair] - accInit0)
				neonDeltaOddRaw := uint16(naccNEON[pair+1] - accInit1)
				neonDeltaEven := fieldReduceOnce(neonDeltaEvenRaw)
				neonDeltaOdd := fieldReduceOnce(neonDeltaOddRaw)

				t.Fatalf("iter=%d idx=%d: internalNTTMulAccNEON mismatch: got=%d want=%d pair=%d a0=%d a1=%d b0=%d b1=%d initAccEven=%d initAccOdd=%d refEvenDelta=%d refOddDelta=%d refAB00=%d refAB11=%d refAB01=%d refAB10=%d refAccEven=%d refAccOdd=%d neonDeltaEvenRaw=%d neonDeltaOddRaw=%d neonDeltaEven=%d neonDeltaOdd=%d",
					i, j, naccNEON[j], naccRef[j], pair/2, a0, a1, b0, b1, accInit0, accInit1, evenDelta, oddDelta, ab00, ab11, ab01, ab10, acc0, acc1, neonDeltaEvenRaw, neonDeltaOddRaw, neonDeltaEven, neonDeltaOdd)
			}
		}
	}
}

func TestNEONNTTMulAccKeyGenMatchesMontgomery(t *testing.T) {
	for i := 0; i < 100; i++ {
		lhs := randomRingElement()
		rhs := randomRingElement()
		accNEON := randomRingElement()
		accRef := accNEON

		internalMontNTT(&lhs)
		internalMontNTT(&rhs)
		internalMontNTT(&accNEON)
		internalMontNTT(&accRef)

		nlhs := nttElement(lhs)
		nrhs := nttElement(rhs)
		naccNEON := nttElement(accNEON)
		naccRef := nttElement(accRef)

		internalNTTMulAccKeyGenNEON(&naccNEON, &nlhs, &nrhs)
		nttMulAccGeneric(&naccRef, &nlhs, &nrhs)

		for j := range naccNEON {
			if naccNEON[j] != naccRef[j] {
				t.Fatalf("iter=%d idx=%d: NTTMulAccKeyGen mismatch: got=%d want=%d", i, j, naccNEON[j], naccRef[j])
			}
		}
	}
}

func BenchmarkNTTForwardNEON(b *testing.B) {
	elem := randomRingElement()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := elem
		internalNTTNEON(&elem2)
	}
}

func BenchmarkNTTInverseNEON(b *testing.B) {
	elem := randomRingElement()
	internalNTTNEON(&elem)
	ntElem := nttElement(elem)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := ntElem
		internalInverseNTTNEON(&elem2)
	}
}

func BenchmarkNTTRoundTripNEON(b *testing.B) {
	elem := randomRingElement()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		elem2 := elem
		internalNTT(&elem2)
		internalInverseNTT((*nttElement)(&elem2))
	}
}

func BenchmarkNTTMulAccNEON(b *testing.B) {
	lhs := randomRingElement()
	rhs := randomRingElement()
	acc := randomRingElement()
	internalNTTNEON(&lhs)
	internalNTTNEON(&rhs)
	internalNTTNEON(&acc)
	nlhs := nttElement(lhs)
	nrhs := nttElement(rhs)
	nacc := nttElement(acc)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acc2 := nacc
		internalNTTMulAccNEON(&acc2, &nlhs, &nrhs)
	}
}

func BenchmarkNTTMulAccKeyGenNEON(b *testing.B) {
	lhs := randomRingElement()
	rhs := randomRingElement()
	acc := randomRingElement()
	internalNTTNEON(&lhs)
	internalNTTNEON(&rhs)
	internalNTTNEON(&acc)
	nlhs := nttElement(lhs)
	nrhs := nttElement(rhs)
	nacc := nttElement(acc)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acc2 := nacc
		internalNTTMulAccKeyGenNEON(&acc2, &nlhs, &nrhs)
	}
}

func TestSamplePolyCBD2NEONMatchesGeneric(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		var seed [32]byte
		for i := range seed {
			seed[i] = byte(iter*256 + i)
		}

		// Build 128-byte input for eta=2
		var B [128]byte
		for i := 0; i < 128; i++ {
			B[i] = byte((seed[i%32] + byte(i)) ^ 0xAA)
		}

		// Compute via NEON path
		gotNEON := ringElement{}
		samplePolyCBD2NEON(&gotNEON, &B)

		// Compute via generic path
		wantGeneric := samplePolyCBDGeneric(B[:], 2)

		// Compare all coefficients
		for i := range gotNEON {
			if gotNEON[i] != wantGeneric[i] {
				t.Fatalf("iter=%d coeff=%d: samplePolyCBD2NEON mismatch: got=%d want=%d", iter, i, gotNEON[i], wantGeneric[i])
			}
		}
	}
}

func TestSamplePolyCBD3Arm64MatchesGeneric(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		var seed [32]byte
		for i := range seed {
			seed[i] = byte(iter*256 + i)
		}

		// Build 192-byte input for eta=3
		var B [192]byte
		for i := 0; i < 192; i++ {
			B[i] = byte((seed[i%32] + byte(i)) ^ 0x55)
		}

		// Compute via Arm64 path
		gotArm64 := samplePolyCBD3Arm64(&B)

		// Compute via generic path
		wantGeneric := samplePolyCBDGeneric(B[:], 3)

		// Compare all coefficients
		for i := range gotArm64 {
			if gotArm64[i] != wantGeneric[i] {
				t.Fatalf("iter=%d coeff=%d: samplePolyCBD3Arm64 mismatch: got=%d want=%d", iter, i, gotArm64[i], wantGeneric[i])
			}
		}
	}
}

func TestSamplePolyCBDDispatchEta2(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		var seed [32]byte
		for i := range seed {
			seed[i] = byte(iter*256 + i)
		}

		// Compute via dispatch (should route to NEON for eta=2 on arm64)
		gotDispatch := samplePolyCBD(seed[:], byte(iter), 2)

		// Compute via generic
		var B [128]byte
		prf := sha3.NewSHAKE256()
		prf.Write(seed[:])
		prf.Write([]byte{byte(iter)})
		prf.Read(B[:])
		wantGeneric := samplePolyCBDGeneric(B[:], 2)

		for i := range gotDispatch {
			if gotDispatch[i] != wantGeneric[i] {
				t.Fatalf("iter=%d coeff=%d: dispatch eta=2 mismatch: got=%d want=%d", iter, i, gotDispatch[i], wantGeneric[i])
			}
		}
	}
}

func BenchmarkSamplePolyCBD2NEON(b *testing.B) {
	var B [128]byte
	for i := range B {
		B[i] = byte(i)
	}
	var f ringElement
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		samplePolyCBD2NEON(&f, &B)
	}
}

func BenchmarkSamplePolyCBD3Arm64(b *testing.B) {
	var B [192]byte
	for i := range B {
		B[i] = byte(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = samplePolyCBD3Arm64(&B)
	}
}
