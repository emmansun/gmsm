// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package adxmodel

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand/v2"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

// The pre-fix ADOX reduction chain corrupted the result whenever a reduction
// intermediate r[k] landed in the signed-overflow window of the SBB chain:
//
//	CF=0: r[k] in [0x8000000000000000, 0x8000000080000000)
//	CF=1: r[k] in [0x8000000000000000, 0x8000000080000000]
//
// The window is 2^31 wide out of 2^64 per reduction step, hence the roughly
// 2^-33 failure probability per multiplication observed in issue #560.
const (
	windowLo = 0x8000000000000000
	windowHi = 0x8000000080000000

	// seedHigh, seedLow fix the PCG seed of the generator so the committed
	// vectors are exactly reproducible.
	seedHigh = 0x676d736d // "gmsm"
	seedLow  = 0x00000560 // issue 560
)

// inv64 returns the multiplicative inverse of odd a modulo 2^64 by Newton
// iteration (Hensel lifting, doubling the correct low bits per round).
func inv64(a uint64) uint64 {
	x := a // correct modulo 2^3 for odd a
	for i := 0; i < 5; i++ {
		x *= 2 - a*x
	}
	return x
}

// randomLow returns a random 32-bit value. Generated operands keep their high
// limbs small so that a and b are canonical field elements below p, which is
// the domain real callers use.
func randomLow(rng *rand.Rand) uint64 {
	return rng.Uint64N(1 << 32)
}

// windowValue samples a target inside the corrupting window.
func windowValue(rng *rand.Rand) uint64 {
	return windowLo + rng.Uint64N(windowHi-windowLo)
}

// BuildRed0Hit constructs a and b whose first reduction intermediate r[0] is
// forced into the overflow window. r[0] = lo(a[0]*b[0]), so with b[0] odd we
// solve a[0] = target * b[0]^-1 (mod 2^64); the remaining limbs are free.
func BuildRed0Hit(rng *rand.Rand) (a, b [4]uint64) {
	b0 := rng.Uint64() | 1
	target := windowValue(rng)
	a[0] = target * inv64(b0)
	b[0] = b0
	a[1], a[2], a[3] = randomLow(rng), randomLow(rng), randomLow(rng)
	b[1], b[2], b[3] = randomLow(rng), randomLow(rng), randomLow(rng)
	return a, b
}

// BuildRed1Hit constructs a and b whose second reduction intermediate r[1]
// is forced into the overflow window. r[1] at that point equals
// C(a[0],a[1],b[0]) + lo(a[0]*b[1]), so with a[0] odd we first measure C
// with b[1]=0 and then solve b[1] = (target - C) * a[0]^-1 (mod 2^64).
func BuildRed1Hit(rng *rand.Rand) (a, b [4]uint64) {
	a0 := rng.Uint64() | 1
	a1 := randomLow(rng)
	b0 := randomLow(rng)
	c := MontgomeryMul([4]uint64{a0, a1, 0, 0}, [4]uint64{b0, 0, 0, 0}, ADOX).Steps[1].Acc
	target := windowValue(rng)
	b1 := (target - c) * inv64(a0)
	a = [4]uint64{a0, a1, randomLow(rng), randomLow(rng)}
	b = [4]uint64{b0, b1, randomLow(rng), randomLow(rng)}
	return a, b
}

// ReferenceMul computes a*b*2^-256 mod q with math/big, independently of the
// simulator, and returns the result limbs. It is the correctness oracle for
// the model.
//
// q is the SM2 field prime 2^256 - 2^224 - 2^96 + 2^64 - 1, which must not be
// confused with the SM2 group order n = 0xfffffffe...7203df6b21c6052b53bbf40939d54123.
func ReferenceMul(a, b [4]uint64) [4]uint64 {
	p, _ := new(big.Int).SetString("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", 16)
	r := new(big.Int).Lsh(big.NewInt(1), 256)
	rinv := new(big.Int).ModInverse(r, p)
	t := new(big.Int).Mul(limbsToBig(a), limbsToBig(b))
	t.Mod(t, p)
	t.Mul(t, rinv)
	t.Mod(t, p)
	var be [32]byte
	t.FillBytes(be[:])
	return LimbsFromBigEndian(&be)
}

func limbsToBig(in [4]uint64) *big.Int {
	be := BigEndianFromLimbs(in)
	return new(big.Int).SetBytes(be[:])
}

// CaseFlags are the flags attached to generated vectors.
const (
	FlagCarryTail = "ADXCarryTail"
	FlagRedStep0  = "ReductionStep0"
	FlagRedStep1  = "ReductionStep1"
)

// vectorName is the committed file name of the generated suite.
const vectorName = "sm2ec_p256_mul_bmi2.json"

// SuiteFileName returns the committed vector file name produced by
// GenerateSuite.
func SuiteFileName() string { return vectorName }

// GenerateSuite builds the SM2EC p256Mul BMI2 boundary suite. The output is
// deterministic; TestVectorsUpToDate in this package regenerates it and
// compares it with the committed file.
func GenerateSuite() (*vectors.Suite, error) {
	rng := rand.New(rand.NewPCG(seedHigh, seedLow))

	// The vector from issue #560 itself: a real signature verification
	// failure, reduced to the field multiplication that first diverged.
	knownA := [4]uint64{0x9e33db4ce976f0d0, 0xbfff13c7cf9058cc, 0xe1a0b4b129d5a082, 0xaab573c26f5a3de8}
	knownB := [4]uint64{0xefb0ad3e4d98a44c, 0xdd1c0e16a5de4d21, 0xe02fe084a848fecf, 0x0d0047be9622130f}

	tests := []vectors.Case{
		newCase(1, knownA, knownB,
			"issue #560: the multiplication p256Inverse first diverged on",
			[]string{FlagCarryTail, "KnownBadVector"}),
	}

	id := 2
	for i := 0; i < 3; i++ {
		a, b := BuildRed0Hit(rng)
		tests = append(tests, newCase(id, a, b,
			"constructed: r[0] forced into the SBB overflow window",
			[]string{FlagCarryTail, FlagRedStep0}))
		id++
	}
	for i := 0; i < 3; i++ {
		a, b := BuildRed1Hit(rng)
		tests = append(tests, newCase(id, a, b,
			"constructed: r[1] forced into the SBB overflow window",
			[]string{FlagCarryTail, FlagRedStep1}))
		id++
	}

	// Every case must have broken the pre-fix code and must agree with the
	// independent big.Int oracle. The same operands also pin p256Sqr with n=1:
	// its macro reduces through the CF chain (ADD/ADC), so it was never exposed
	// to the OF chain of issue #560, but the cases guard the path against a
	// future ADX rewrite.
	var sqrTests []vectors.Case
	for i := range tests {
		c := &tests[i]
		aBE, err := vectors.DecodeHex32(c.A)
		if err != nil {
			return nil, err
		}
		bBE, err := vectors.DecodeHex32(c.B)
		if err != nil {
			return nil, err
		}
		a, b := LimbsFromBigEndian(&aBE), LimbsFromBigEndian(&bBE)
		fixed := MontgomeryMul(a, b, ADCX).R
		old := MontgomeryMul(a, b, ADOX).R
		if fixed == old {
			return nil, fmt.Errorf("vectors: tc%d does not distinguish the ADOX and ADCX reduction chains", c.TCID)
		}
		if want := ReferenceMul(a, b); fixed != want {
			return nil, fmt.Errorf("vectors: tc%d model diverges from big.Int reference\nmodel: %x\nref:   %x", c.TCID, fixed, want)
		}
		sqrTests = append(sqrTests, vectors.Case{
			TCID:     c.TCID,
			Comment:  fmt.Sprintf("p256Sqr, n=1, on the operand of FieldMul tc%d", c.TCID),
			Flags:    c.Flags,
			A:        c.A,
			Expected: hex.EncodeToString(beBytes(ReferenceMul(a, a))),
		})
	}

	return &vectors.Suite{
		Schema:    "gmsm-kernel-vectors/v1",
		Algorithm: "sm2p256v1",
		Generator: "internal/cryptotest/adxmodel, deterministic PCG seed (0x676d736d, 0x560); run `go test ./internal/cryptotest/adxmodel -run TestVectorsUpToDate -update` to regenerate",
		Groups: []vectors.Group{{
			Type:     "FieldMul",
			Arch:     []string{"amd64"},
			Features: []string{"adx", "bmi2"},
			Comment: "p256Mul (mulBMI2) Montgomery multiplication. Inputs are canonical field elements; " +
				"expected is the exact Montgomery result. Cases marked ADXCarryTail corrupt the pre-fix " +
				"ADOX reduction chain (issue #560) and must pass on both the BMI2 and the generic path.",
			Tests: tests,
		}, {
			Type:     "FieldSqr",
			Arch:     []string{"amd64"},
			Features: []string{"adx", "bmi2"},
			Comment: "p256Sqr with n=1 (Montgomery squaring). The sqr macro reduces through the CF " +
				"chain, so it is listed for boundary coverage of the squaring path, not as an issue " +
				"#560 trigger. Expected is the exact Montgomery square of a.",
			Tests: sqrTests,
		}},
	}, nil
}

func newCase(id int, a, b [4]uint64, comment string, flags []string) vectors.Case {
	return vectors.Case{
		TCID:     id,
		Comment:  comment,
		Flags:    flags,
		A:        hex.EncodeToString(beBytes(a)),
		B:        hex.EncodeToString(beBytes(b)),
		Expected: hex.EncodeToString(beBytes(MontgomeryMul(a, b, ADCX).R)),
	}
}

func beBytes(in [4]uint64) []byte {
	be := BigEndianFromLimbs(in)
	return be[:]
}

// MarshalSuite renders a suite as the committed JSON representation.
func MarshalSuite(s *vectors.Suite) ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
