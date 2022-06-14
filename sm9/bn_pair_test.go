package sm9

import (
	"encoding/hex"
	"math/big"
	"testing"
)

var expected1 = &gfP12{}
var expected_b2 = &gfP12{}
var expected_b2_2 = &gfP12{}

func init() {
	expected1.x.x.x = *fromBigInt(bigFromHex("4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d"))
	expected1.x.x.y = *fromBigInt(bigFromHex("28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000"))
	expected1.x.y.x = *fromBigInt(bigFromHex("38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f"))
	expected1.x.y.y = *fromBigInt(bigFromHex("a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db"))
	expected1.y.x.x = *fromBigInt(bigFromHex("67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f"))
	expected1.y.x.y = *fromBigInt(bigFromHex("5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6"))
	expected1.y.y.x = *fromBigInt(bigFromHex("1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b"))
	expected1.y.y.y = *fromBigInt(bigFromHex("93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439"))
	expected1.z.x.x = *fromBigInt(bigFromHex("b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d"))
	expected1.z.x.y = *fromBigInt(bigFromHex("4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b"))
	expected1.z.y.x = *fromBigInt(bigFromHex("84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a"))
	expected1.z.y.y = *fromBigInt(bigFromHex("aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb"))

	expected_b2.x.x.x = *fromBigInt(bigFromHex("28542FB6954C84BE6A5F2988A31CB6817BA0781966FA83D9673A9577D3C0C134"))
	expected_b2.x.x.y = *fromBigInt(bigFromHex("5E27C19FC02ED9AE37F5BB7BE9C03C2B87DE027539CCF03E6B7D36DE4AB45CD1"))
	expected_b2.x.y.x = *fromBigInt(bigFromHex("A1ABFCD30C57DB0F1A838E3A8F2BF823479C978BD137230506EA6249C891049E"))
	expected_b2.x.y.y = *fromBigInt(bigFromHex("3497477913AB89F5E2960F382B1B5C8EE09DE0FA498BA95C4409D630D343DA40"))
	expected_b2.y.x.x = *fromBigInt(bigFromHex("4FEC93472DA33A4DB6599095C0CF895E3A7B993EE5E4EBE3B9AB7D7D5FF2A3D1"))
	expected_b2.y.x.y = *fromBigInt(bigFromHex("647BA154C3E8E185DFC33657C1F128D480F3F7E3F16801208029E19434C733BB"))
	expected_b2.y.y.x = *fromBigInt(bigFromHex("73F21693C66FC23724DB26380C526223C705DAF6BA18B763A68623C86A632B05"))
	expected_b2.y.y.y = *fromBigInt(bigFromHex("0F63A071A6D62EA45B59A1942DFF5335D1A232C9C5664FAD5D6AF54C11418B0D"))
	expected_b2.z.x.x = *fromBigInt(bigFromHex("8C8E9D8D905780D50E779067F2C4B1C8F83A8B59D735BB52AF35F56730BDE5AC"))
	expected_b2.z.x.y = *fromBigInt(bigFromHex("861CCD9978617267CE4AD9789F77739E62F2E57B48C2FF26D2E90A79A1D86B93"))
	expected_b2.z.y.x = *fromBigInt(bigFromHex("9B1CA08F64712E33AEDA3F44BD6CB633E0F722211E344D73EC9BBEBC92142765"))
	expected_b2.z.y.y = *fromBigInt(bigFromHex("6BA584CE742A2A3AB41C15D3EF94EDEB8EF74A2BDCDAAECC09ABA567981F6437"))

	expected_b2_2.x.x.x = *fromBigInt(bigFromHex("1052D6E9D13E381909DFF7B2B41E13C987D0A9068423B769480DACCE6A06F492"))
	expected_b2_2.x.x.y = *fromBigInt(bigFromHex("5FFEB92AD870F97DC0893114DA22A44DBC9E7A8B6CA31A0CF0467265A1FB48C7"))
	expected_b2_2.x.y.x = *fromBigInt(bigFromHex("2C5C3B37E4F2FF83DB33D98C0317BCBBBBF4AC6DF6B89ECA58268B280045E612"))
	expected_b2_2.x.y.y = *fromBigInt(bigFromHex("6CED9E2D7C9CD3D5AD630DEFAB0B831506218037EE0F861CF9B43C78434AEC38"))
	expected_b2_2.y.x.x = *fromBigInt(bigFromHex("0AE7BF3E1AEC0CB67A03440906C7DFB3BCD4B6EEEBB7E371F0094AD4A816088D"))
	expected_b2_2.y.x.y = *fromBigInt(bigFromHex("98DBC791D0671CACA12236CDF8F39E15AEB96FAEB39606D5B04AC581746A663D"))
	expected_b2_2.y.y.x = *fromBigInt(bigFromHex("00DD2B7416BAA91172E89D5309D834F78C1E31B4483BB97185931BAD7BE1B9B5"))
	expected_b2_2.y.y.y = *fromBigInt(bigFromHex("7EBAC0349F8544469E60C32F6075FB0468A68147FF013537DF792FFCE024F857"))
	expected_b2_2.z.x.x = *fromBigInt(bigFromHex("10CC2B561A62B62DA36AEFD60850714F49170FD94A0010C6D4B651B64F3A3A5E"))
	expected_b2_2.z.x.y = *fromBigInt(bigFromHex("58C9687BEDDCD9E4FEDAB16B884D1FE6DFA117B2AB821F74E0BF7ACDA2269859"))
	expected_b2_2.z.y.x = *fromBigInt(bigFromHex("2A430968F16086061904CE201847934B11CA0F9E9528F5A9D0CE8F015C9AEA79"))
	expected_b2_2.z.y.y = *fromBigInt(bigFromHex("934FDDA6D3AB48C8571CE2354B79742AA498CB8CDDE6BD1FA5946345A1A652F6"))
}

func Test_gfpBasicOperations(t *testing.T) {
	x := fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141"))
	y := fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B"))
	expectedAdd := fromBigInt(bigFromHex("0691692307d370af56226e57920199fbbe10f216c67fbc9468c7f225a4b1f21f"))
	expectedSub := fromBigInt(bigFromHex("67b381821c52a5624f3304a8149be8461e3bc07adcb872c38aa65051ba53ba97"))
	expectedNeg := fromBigInt(bigFromHex("7f1d8aad70909be90358f1d02240062433cc3a0248ded72febb879ec33ce6f22"))
	expectedMul := fromBigInt(bigFromHex("3d08bbad376584e4f74bd31f78f716372b96ba8c3f939c12b8d54e79b6489e76"))

	ret := &gfP{}
	gfpAdd(ret, x, y)
	if *expectedAdd != *ret {
		t.Errorf("add not same")
	}

	gfpSub(ret, y, x)
	if *expectedSub != *ret {
		t.Errorf("sub not same")
	}

	gfpNeg(ret, y)
	if *expectedNeg != *ret {
		t.Errorf("neg not same")
	}

	gfpMul(ret, x, y)
	if *expectedMul != *ret {
		t.Errorf("mul not same")
	}
}

func TestGfpExp(t *testing.T) {
	xI := bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")
	x := fromBigInt(xI)
	ret := &gfP{}
	ret.exp(x, pMinus2)

	ret1 := &gfP{}
	ret1.exp2(x, bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457b"))
	if ret1.String() == ret.String() {
		t.Errorf("exp not same")
	}

	ret2 := new(big.Int).Exp(xI, bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457b"), p)
	if hex.EncodeToString(ret2.Bytes()) == ret.String() {
		t.Errorf("exp not same")
	}

	xInv := new(big.Int).ModInverse(xI, p)
	if hex.EncodeToString(ret2.Bytes()) != hex.EncodeToString(xInv.Bytes()) {
		t.Errorf("exp not same, got %v, expected %v\n", hex.EncodeToString(ret2.Bytes()), hex.EncodeToString(xInv.Bytes()))
	}
}

func TestGfpInvert(t *testing.T) {
	x := fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	xInv := &gfP{}
	xInv.Invert(x)
	y := &gfP{}
	gfpMul(y, x, xInv)
	if *y != *one {
		t.Errorf("got %v, expected %v", y, one)
	}
}

func TestGfpDiv(t *testing.T) {
	x := fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	ret := &gfP{}
	ret.Div2(x)
	gfpAdd(ret, ret, ret)
	if *ret != *x {
		t.Errorf("got %v, expected %v", ret, x)
	}
}

func TestGfpSqrt(t *testing.T) {
	tests := []string{
		"9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596",
		"92fe90b700fbd4d8cc177d300ed16e4e15471a681b2c9e3728c1b82c885e49c2",
	}
	for i, test := range tests {
		y2 := bigFromHex(test)
		y21 := new(big.Int).ModSqrt(y2, p)

		y3 := new(big.Int).Mul(y21, y21)
		y3.Mod(y3, p)
		if y2.Cmp(y3) != 0 {
			t.Error("Invalid sqrt")
		}

		tmp := fromBigInt(y2)
		tmp.Sqrt(tmp)
		montDecode(tmp, tmp)
		var res [32]byte
		tmp.Marshal(res[:])
		if hex.EncodeToString(res[:]) != hex.EncodeToString(y21.Bytes()) {
			t.Errorf("case %v, got %v, expected %v\n", i, hex.EncodeToString(res[:]), hex.EncodeToString(y21.Bytes()))
		}
	}
}

func Test_Pairing_A2(t *testing.T) {
	pk := bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	g2 := &G2{}
	g2.ScalarBaseMult(pk)
	ret := pairing(g2.p, curveGen)
	if ret.x != expected1.x || ret.y != expected1.y || ret.z != expected1.z {
		t.Errorf("not expected")
	}
}

func Test_Pairing_B2(t *testing.T) {
	deB := &twistPoint{}
	deB.x.x = *fromBigInt(bigFromHex("74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7"))
	deB.x.y = *fromBigInt(bigFromHex("01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2"))
	deB.y.x = *fromBigInt(bigFromHex("44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1"))
	deB.y.y = *fromBigInt(bigFromHex("8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539"))
	deB.z.SetOne()
	deB.t.SetOne()

	rA := &curvePoint{}
	rA.x = *fromBigInt(bigFromHex("7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265"))
	rA.y = *fromBigInt(bigFromHex("A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599"))
	rA.z = *one
	rA.t = *one

	ret := pairing(deB, rA)
	if ret.x != expected_b2.x || ret.y != expected_b2.y || ret.z != expected_b2.z {
		t.Errorf("not expected")
	}
}

func Test_Pairing_B2_2(t *testing.T) {
	pubE := &curvePoint{}
	pubE.x = *fromBigInt(bigFromHex("9174542668E8F14AB273C0945C3690C66E5DD09678B86F734C4350567ED06283"))
	pubE.y = *fromBigInt(bigFromHex("54E598C6BF749A3DACC9FFFEDD9DB6866C50457CFC7AA2A4AD65C3168FF74210"))
	pubE.z = *one
	pubE.t = *one

	ret := pairing(twistGen, pubE)
	ret.Exp(ret, bigFromHex("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE"))
	if ret.x != expected_b2_2.x || ret.y != expected_b2_2.y || ret.z != expected_b2_2.z {
		t.Errorf("not expected")
	}
}

func Test_finalExponentiation(t *testing.T) {
	x := &gfP12{
		gfP4{
			gfP2{
				*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				*fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				*fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
	}
	got := finalExponentiation(x)

	exp := new(big.Int).Exp(p, big.NewInt(12), nil)
	exp.Sub(exp, big.NewInt(1))
	exp.Div(exp, Order)
	expected := (&gfP12{}).Exp(x, exp)

	if got.x != expected.x || got.y != expected.y || got.z != expected.z {
		t.Errorf("got %v, expected %v\n", got, expected)
	}
}
