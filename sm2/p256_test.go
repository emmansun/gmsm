package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

type baseMultTest struct {
	k string
}

var baseMultTests = []baseMultTest{
	{
		"112233445566778899",
	},
	{
		"112233445566778899112233445566778899",
	},
	{
		"6950511619965839450988900688150712778015737983940691968051900319680",
	},
	{
		"13479972933410060327035789020509431695094902435494295338570602119423",
	},
	{
		"13479971751745682581351455311314208093898607229429740618390390702079",
	},
	{
		"13479972931865328106486971546324465392952975980343228160962702868479",
	},
	{
		"11795773708834916026404142434151065506931607341523388140225443265536",
	},
	{
		"784254593043826236572847595991346435467177662189391577090",
	},
	{
		"13479767645505654746623887797783387853576174193480695826442858012671",
	},
	{
		"205688069665150753842126177372015544874550518966168735589597183",
	},
	{
		"13479966930919337728895168462090683249159702977113823384618282123295",
	},
	{
		"50210731791415612487756441341851895584393717453129007497216",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368041",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368042",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368043",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368044",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368045",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368046",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368047",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368048",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368049",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368050",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368051",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368052",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368053",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368054",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368055",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368056",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368057",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368058",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368059",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368060",
	},
}

type scalarMultTest struct {
	k          string
	xIn, yIn   string
	xOut, yOut string
}

var p256MultTests = []scalarMultTest{
	{
		"9e9e0dfa7b29bd78a381e5ad3c3ef3154080bf8198b4f6d4dc4b13a04e49a979",
		"0a5351c475d8f8c5dab77b688b17fa1d6f2a9aed187b3a6cb670647c1a1b2369",
		"aba5ace91a313f0d4468a44f66617e7f497f3508c6f2c0273dc6c133c9a59df0",
		"f64634b9eb2b0feb5bfdcb882a365041437da717dfb4156e7b3f3b22784889a9",
		"84d36430a453396b047494e6a74c43abf193c13ce17dd60b614b22de97139d09",
	},
	{
		"dd242eb66c7be62f2d3173185b6875f66d0d0bc75df8900c69d48630ef60faff",
		"0f5e36b3eaa03868bccfd0f7e5f0189ee5d58b0946420ee0672797620f4856df",
		"35032c2d743a0df6d838b01034402db85d3ad4b07f316612cfc8902434dedd29",
		"1ffe871e928012e14dfad0ec1d54a8198c6830dd283703a42c21f2367c72d10f",
		"fbf401d0729d2b38a925d2d2b750293239ea74065a28279710e5fc8a7c86b3b7",
	},
	{
		"38f2411d1cad8c1b026e731a85dcc2eca79f472369233ae204aa5d6a2f6542f1",
		"1fb1c5de8ef2fdecf9a729ed4eb9ce0f363e75fed95400dbd25c333c26393bc3",
		"e9250c58d7200783aa9ec9814c13f252ba368bf52d6fd8f2e9397e603972e55d",
		"b5301fcc9818019651e8f56a265fb254ad864d9001b21ebd6b1a6ec0e6f6e07a",
		"2e29cd8f8697360d0b60d730d073793d41bc3c99f00c99875f5d22ed0b32ea6a",
	},
}

func genericParamsForCurve(c elliptic.Curve) *elliptic.CurveParams {
	d := *(c.Params())
	return &d
}

func TestP256BaseMult(t *testing.T) {
	p256 := P256()
	p256Generic := genericParamsForCurve(p256)

	scalars := make([]*big.Int, 0, len(baseMultTests)+1)
	for i := 1; i <= 20; i++ {
		k := new(big.Int).SetInt64(int64(i))
		scalars = append(scalars, k)
	}
	for _, e := range baseMultTests {
		k, _ := new(big.Int).SetString(e.k, 10)
		scalars = append(scalars, k)
	}
	k := new(big.Int).SetInt64(1)
	k.Lsh(k, 500)
	scalars = append(scalars, k)

	for i, k := range scalars {
		x, y := p256.ScalarBaseMult(k.Bytes())
		x2, y2 := p256Generic.ScalarBaseMult(k.Bytes())
		if x.Cmp(x2) != 0 || y.Cmp(y2) != 0 {
			t.Errorf("#%d: got (%x, %x), want (%x, %x)", i, x, y, x2, y2)
		}

		if testing.Short() && i > 5 {
			break
		}
	}
}

func generateP256MultTests() {
	p256 := P256()
	p256Generic := genericParamsForCurve(p256)
	for i := 0; i < 3; i++ {
		k1, err := randFieldElement(p256Generic, rand.Reader)
		if err != nil {
			fmt.Printf("%v\n", err)
		}
		x1, y1 := p256Generic.ScalarBaseMult(k1.Bytes())
		k2, err := randFieldElement(p256Generic, rand.Reader)
		if err != nil {
			fmt.Printf("%v\n", err)
		}
		x2, y2 := p256Generic.ScalarMult(x1, y1, k2.Bytes())
		fmt.Printf("%s\n", hex.EncodeToString(k2.Bytes()))
		fmt.Printf("%s\n", hex.EncodeToString(x1.Bytes()))
		fmt.Printf("%s\n", hex.EncodeToString(y1.Bytes()))
		fmt.Printf("%s\n", hex.EncodeToString(x2.Bytes()))
		fmt.Printf("%s\n", hex.EncodeToString(y2.Bytes()))
	}
}

func TestP256Mult(t *testing.T) {
	p256 := P256()
	for i, e := range p256MultTests {
		x, _ := new(big.Int).SetString(e.xIn, 16)
		y, _ := new(big.Int).SetString(e.yIn, 16)
		k, _ := new(big.Int).SetString(e.k, 16)
		expectedX, _ := new(big.Int).SetString(e.xOut, 16)
		expectedY, _ := new(big.Int).SetString(e.yOut, 16)

		xx, yy := p256.ScalarMult(x, y, k.Bytes())
		if xx.Cmp(expectedX) != 0 || yy.Cmp(expectedY) != 0 {
			t.Errorf("#%d: got (%x, %x), want (%x, %x)", i, xx, yy, expectedX, expectedY)
		}
	}
}

type synthCombinedMult struct {
	elliptic.Curve
}

func (s synthCombinedMult) CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int) {
	x1, y1 := s.ScalarBaseMult(baseScalar)
	x2, y2 := s.ScalarMult(bigX, bigY, scalar)
	return s.Add(x1, y1, x2, y2)
}

func TestP256CombinedMult(t *testing.T) {
	type combinedMult interface {
		elliptic.Curve
		CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
	}

	p256, ok := P256().(combinedMult)
	if !ok {
		p256 = &synthCombinedMult{P256()}
	}

	gx := p256.Params().Gx
	gy := p256.Params().Gy

	zero := make([]byte, 32)
	one := make([]byte, 32)
	one[31] = 1
	two := make([]byte, 32)
	two[31] = 2

	// 0×G + 0×G = ∞
	x, y := p256.CombinedMult(gx, gy, zero, zero)
	if x.Sign() != 0 || y.Sign() != 0 {
		t.Errorf("0×G + 0×G = (%d, %d), should be ∞", x, y)
	}

	// 1×G + 0×G = G
	x, y = p256.CombinedMult(gx, gy, one, zero)
	if x.Cmp(gx) != 0 || y.Cmp(gy) != 0 {
		t.Errorf("1×G + 0×G = (%d, %d), should be (%d, %d)", x, y, gx, gy)
	}

	// 0×G + 1×G = G
	x, y = p256.CombinedMult(gx, gy, zero, one)
	if x.Cmp(gx) != 0 || y.Cmp(gy) != 0 {
		t.Errorf("0×G + 1×G = (%d, %d), should be (%d, %d)", x, y, gx, gy)
	}

	// 1×G + 1×G = 2×G
	x, y = p256.CombinedMult(gx, gy, one, one)
	ggx, ggy := p256.ScalarBaseMult(two)
	if x.Cmp(ggx) != 0 || y.Cmp(ggy) != 0 {
		t.Errorf("1×G + 1×G = (%d, %d), should be (%d, %d)", x, y, ggx, ggy)
	}

	minusOne := new(big.Int).Sub(p256.Params().N, big.NewInt(1))
	// 1×G + (-1)×G = ∞
	x, y = p256.CombinedMult(gx, gy, one, minusOne.Bytes())
	if x.Sign() != 0 || y.Sign() != 0 {
		t.Errorf("1×G + (-1)×G = (%d, %d), should be ∞", x, y)
	}
}
