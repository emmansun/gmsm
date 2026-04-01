// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego

package mlkem

import (
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
