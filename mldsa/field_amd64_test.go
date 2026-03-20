//go:build amd64 && !purego

package mldsa

import "testing"

func TestInternalNTTAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		r := randomRingElement()

		got := r
		internalNTTAVX2(&got)

		want := r
		internalNTTGeneric(&want)

		if got != want {
			t.Logf("want: %v", want)
			t.Logf("got:  %v", got)
			t.Fatalf("internalNTTAVX2 mismatch on iteration %d", i)
		}
	}
}

func TestNTTMulAVX2(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 is not available")
	}

	for i := 0; i < 16; i++ {
		left := ntt(randomRingElement())
		right := ntt(randomRingElement())

		var got nttElement
		nttMulAVX2(&left, &right, &got)

		var want nttElement
		nttMulGeneric(&want, &left, &right)
		if got != want {
			t.Fatalf("nttMulAVX2 mismatch on iteration %d", i)
		}
	}
}

func TestNTTMul(t *testing.T) {
	for i := 0; i < 16; i++ {
		left := ntt(randomRingElement())
		right := ntt(randomRingElement())

		var got nttElement
		nttMul(&got, &left, &right)

		var want nttElement
		nttMulGeneric(&want, &left, &right)
		if got != want {
			t.Fatalf("nttMulInto mismatch on iteration %d", i)
		}
	}
}
