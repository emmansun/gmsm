package fiat

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Reference https://github.com/mit-plv/fiat-crypto/blob/master/inversion/c/inversion_template.c
func inverseByDivsteps2(g *[4]uint64) *[4]uint64 {
	var precomp, v, vOut, rOut [4]uint64
	var d, dOut uint64
	var f, fOut, gOut, gs [5]uint64
	var r sm2p256MontgomeryDomainFieldElement
	r1 := (*[4]uint64)(&r)
	sm2p256DivstepPrecomp(&precomp)
	sm2p256Msat(&f)
	sm2p256SetOne(&r)

	copy(gs[:], g[:])

	// 370 = (256 * 49 + 57) / 17 - 1
	for i := 0; i < 370; i++ {
		sm2p256Divstep(&dOut, &fOut, &gOut, &vOut, &rOut, d, &f, &gs, &v, r1)
		sm2p256Divstep(&d, &f, &gs, &v, r1, dOut, &fOut, &gOut, &vOut, &rOut)
	}

	sm2p256Divstep(&dOut, &fOut, &gOut, &vOut, &rOut, d, &f, &gs, &v, r1)

	var out sm2p256MontgomeryDomainFieldElement
	sm2p256Opp(&out, (*sm2p256MontgomeryDomainFieldElement)(&vOut))
	sm2p256Selectznz(&v, (sm2p256Uint1)(fOut[4]>>63), &vOut, (*[4]uint64)(&out))
	sm2p256Mul(&out, (*sm2p256MontgomeryDomainFieldElement)(&v), (*sm2p256MontgomeryDomainFieldElement)(&precomp))

	return (*[4]uint64)(&out)
}

func scalarInverseByDivsteps2(g *[4]uint64) *[4]uint64 {
	var precomp, v, vOut, rOut [4]uint64
	var d, dOut uint64
	var f, fOut, gOut, gs [5]uint64
	var r sm2p256scalarMontgomeryDomainFieldElement
	r1 := (*[4]uint64)(&r)
	sm2p256scalarDivstepPrecomp(&precomp)
	sm2p256scalarMsat(&f)
	sm2p256scalarSetOne(&r)

	copy(gs[:], g[:])

	// 370 = (256 * 49 + 57) / 17 - 1
	for i := 0; i < 370; i++ {
		sm2p256scalarDivstep(&dOut, &fOut, &gOut, &vOut, &rOut, d, &f, &gs, &v, r1)
		sm2p256scalarDivstep(&d, &f, &gs, &v, r1, dOut, &fOut, &gOut, &vOut, &rOut)
	}

	sm2p256scalarDivstep(&dOut, &fOut, &gOut, &vOut, &rOut, d, &f, &gs, &v, r1)

	var out sm2p256scalarMontgomeryDomainFieldElement
	sm2p256scalarOpp(&out, (*sm2p256scalarMontgomeryDomainFieldElement)(&vOut))
	sm2p256scalarSelectznz(&v, (sm2p256scalarUint1)(fOut[4]>>63), &vOut, (*[4]uint64)(&out))
	sm2p256scalarMul(&out, (*sm2p256scalarMontgomeryDomainFieldElement)(&v), (*sm2p256scalarMontgomeryDomainFieldElement)(&precomp))

	return (*[4]uint64)(&out)
}

func TestPrecomp(t *testing.T) {
	pBytes, _ := hex.DecodeString("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff")
	p := new(big.Int).SetBytes(pBytes)
	m := new(big.Int).Add(p, big.NewInt(1))
	m.Rsh(m, 1)
	z := new(big.Int).Exp(m, big.NewInt(741), p)

	v := new(SM2P256Element)
	v.SetBytes(z.Bytes())

	var precomp [4]uint64
	sm2p256DivstepPrecomp(&precomp)

	for i := 0; i < 4; i++ {
		if v.x[i] != precomp[i] {
			t.Errorf("got %x, want %x", v.x[i], precomp[i])
		}
	}
}

var testValues = []string{
	"0000000000000000000000000000000000000000000000000000000000000001",
	"0000000000000000000000000000000000000000000000000000000000000002",
	"0000000000000000000000000000000000000000000000000000000000000003",
	"1000000000000000000000000000000000000000000000000000000000000000",
	"1000000000000000000000000000000000000000000000000000000000000001",
	"1000000000000000000000000000000000000000000000000000000000000002",
	"1000000000000000000000000000000000000000000000000000000000000003",
	"8356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988",
	"981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1",
	"d6833540d019e0438a5dd73b414f26ab43d8064b99671206944e284dbd969093",
	"6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85",
}

func TestInverseByDivsteps2(t *testing.T) {
	for _, v := range testValues {
		vBytes, _ := hex.DecodeString(v)

		in, err := new(SM2P256Element).SetBytes(vBytes)
		if err != nil {
			t.Errorf("SetBytes failed: %v", err)
		}
		in2 := *(*[4]uint64)(&in.x)
		out1 := new(SM2P256Element).Invert(in)
		out1r := (*[4]uint64)(&out1.x)
		out2 := inverseByDivsteps2(&in2)
		tmp := (*sm2p256NonMontgomeryDomainFieldElement)(out2)
		out3 := new(sm2p256MontgomeryDomainFieldElement)
		sm2p256ToMontgomery(out3, tmp)
		if *out3 != *out1r {
			t.Errorf("got %v, want %v", out3, &out1.x)
		}
	}
}

func TestScalarInverseByDivsteps2(t *testing.T) {
	for _, v := range testValues {
		vBytes, _ := hex.DecodeString(v)

		in, err := new(SM2P256OrderElement).SetBytes(vBytes)
		if err != nil {
			t.Errorf("SetBytes failed: %v", err)
		}
		in2 := *(*[4]uint64)(&in.x)
		out1 := new(SM2P256OrderElement).Invert(in)
		out1r := (*[4]uint64)(&out1.x)
		out2 := scalarInverseByDivsteps2(&in2)
		tmp := (*sm2p256scalarNonMontgomeryDomainFieldElement)(out2)
		out3 := new(sm2p256scalarMontgomeryDomainFieldElement)
		sm2p256scalarToMontgomery(out3, tmp)
		if *out3 != *out1r {
			t.Errorf("got %v, want %v", out3, &out1.x)
		}
	}
}

func BenchmarkSm2p256scalarDivstep(b *testing.B) {
	var precomp, v, vOut, rOut [4]uint64
	var d, dOut uint64
	var f, fOut, gOut, gs [5]uint64
	var r sm2p256scalarMontgomeryDomainFieldElement
	r1 := (*[4]uint64)(&r)
	sm2p256scalarDivstepPrecomp(&precomp)
	sm2p256scalarMsat(&f)
	sm2p256scalarSetOne(&r)

	vBytes, _ := hex.DecodeString(testValues[0])

	in, _ := new(SM2P256Element).SetBytes(vBytes)
	g := *(*[4]uint64)(&in.x)
	copy(gs[:], g[:])

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sm2p256scalarDivstep(&dOut, &fOut, &gOut, &vOut, &rOut, d, &f, &gs, &v, r1)
		sm2p256scalarDivstep(&d, &f, &gs, &v, r1, dOut, &fOut, &gOut, &vOut, &rOut)
	}
}

func BenchmarkInverseByDivsteps2(b *testing.B) {
	vBytes, _ := hex.DecodeString(testValues[0])

	in, _ := new(SM2P256Element).SetBytes(vBytes)
	in2 := *(*[4]uint64)(&in.x)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inverseByDivsteps2(&in2)
	}
}

func BenchmarkInvert(b *testing.B) {
	vBytes, _ := hex.DecodeString(testValues[0])

	in, _ := new(SM2P256Element).SetBytes(vBytes)
	out := new(SM2P256Element)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Invert(in)
	}
}

func BenchmarkScalarInverseByDivsteps2(b *testing.B) {
	vBytes, _ := hex.DecodeString(testValues[0])

	in, _ := new(SM2P256OrderElement).SetBytes(vBytes)
	in2 := *(*[4]uint64)(&in.x)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scalarInverseByDivsteps2(&in2)
	}
}

func BenchmarkOrderInvert(b *testing.B) {
	vBytes, _ := hex.DecodeString(testValues[0])

	in, _ := new(SM2P256OrderElement).SetBytes(vBytes)
	out := new(SM2P256OrderElement)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out.Invert(in)
	}
}
