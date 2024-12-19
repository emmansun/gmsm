package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

type CurveParams struct {
	elliptic.CurveParams
	A *big.Int // the constant of the curve equation
}

// polynomial returns x³ +ax + b.
func (curve *CurveParams) polynomial(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	aX := new(big.Int).Mul(curve.A, x)

	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3
}

func (curve *CurveParams) IsOnCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 ||
		y.Sign() < 0 || y.Cmp(curve.P) >= 0 {
		return false
	}

	// y² = x³ + ax + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	return curve.polynomial(x).Cmp(y2) == 0
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. If the point is ∞ it returns 0, 0.
func (curve *CurveParams) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.P)
	return
}

func (curve *CurveParams) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (curve *CurveParams) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/data/shortw/jacobian/addition/add-2007-bl
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, curve.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, curve.P)

	return x3, y3, z3
}

func (curve *CurveParams) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve *CurveParams) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/data/shortw/jacobian/doubling/dbl-2007-bl
	xx := new(big.Int).Mul(x, x)
	xx.Mod(xx, curve.P)
	yy := new(big.Int).Mul(y, y)
	yy.Mod(yy, curve.P)
	yyyy := new(big.Int).Mul(yy, yy)
	yyyy.Mod(yyyy, curve.P)
	zz := new(big.Int).Mul(z, z)
	zz.Mod(zz, curve.P)

	s := new(big.Int).Add(x, yy)
	s.Mul(s, s)
	s.Sub(s, xx)
	if s.Sign() == -1 {
		s.Add(s, curve.P)
	}
	s.Sub(s, yyyy)
	if s.Sign() == -1 {
		s.Add(s, curve.P)
	}
	s.Lsh(s, 1)
	s.Mod(s, curve.P)

	m := new(big.Int).Mul(xx, big.NewInt(3))
	m.Mod(m, curve.P)
	tmp := new(big.Int).Mul(zz, zz)
	tmp.Mul(tmp, curve.A)
	tmp.Mod(tmp, curve.P)
	m.Add(m, tmp)
	m.Mod(m, curve.P)

	t := new(big.Int).Mul(m, m)
	t.Sub(t, s)
	if t.Sign() == -1 {
		t.Add(t, curve.P)
	}
	t.Sub(t, s)
	if t.Sign() == -1 {
		t.Add(t, curve.P)
	}
	t.Mod(t, curve.P)
	x3 := t

	y3 := new(big.Int).Sub(s, t)
	y3.Mul(y3, m)
	yyyy.Lsh(yyyy, 3)
	y3.Sub(y3, yyyy)
	if y3.Sign() == -1 {
		y3.Add(y3, curve.P)
	}
	y3.Mod(y3, curve.P)

	z3 := new(big.Int).Add(y, z)
	z3.Mul(z3, z3)
	z3.Sub(z3, yy)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Sub(z3, zz)
	if z3.Sign() == -1 {
		z3.Add(z3, curve.P)
	}
	z3.Mod(z3, curve.P)

	return x3, y3, z3
}

func (curve *CurveParams) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if byte&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			byte <<= 1
		}
	}

	return curve.affineFromJacobian(x, y, z)
}

func (curve *CurveParams) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("sm2/elliptic: internal error: invalid encoding")
	}
	return b
}

var sampleParams = &CurveParams{
	elliptic.CurveParams{
		Name:    "sampleCurve",
		BitSize: 256,
		P:       bigFromHex("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"),
		N:       bigFromHex("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"),
		B:       bigFromHex("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"),
		Gx:      bigFromHex("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
		Gy:      bigFromHex("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
	},
	bigFromHex("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"),
}

func TestPublicKey(t *testing.T) {
	d := bigFromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
	x, y := sampleParams.ScalarBaseMult(d.Bytes())
	if hex.EncodeToString(x.Bytes()) != "3099093bf3c137d8fcbbcdf4a2ae50f3b0f216c3122d79425fe03a45dbfe1655" ||
		hex.EncodeToString(y.Bytes()) != "3df79e8dac1cf0ecbaa2f2b49d51a4b387f2efaf482339086a27a8e05baed98b" {
		t.FailNow()
	}
	d = bigFromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
	x, y = sampleParams.ScalarBaseMult(d.Bytes())
	if hex.EncodeToString(x.Bytes()) != "245493d446c38d8cc0f118374690e7df633a8a4bfb3329b5ece604b2b4f37f43" ||
		hex.EncodeToString(y.Bytes()) != "53c0869f4b9e17773de68fec45e14904e0dea45bf6cecf9918c85ea047c60a4c" {
		t.FailNow()
	}
}

// calculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func calculateSampleZA(pub *ecdsa.PublicKey, a *big.Int, uid []byte) ([]byte, error) {
	uidLen := len(uid)
	if uidLen >= 0x2000 {
		return nil, errors.New("sm2: the uid is too long")
	}
	entla := uint16(uidLen) << 3
	md := sm3.New()
	md.Write([]byte{byte(entla >> 8), byte(entla)})
	if uidLen > 0 {
		md.Write(uid)
	}
	writeCurveParams(md, pub.Curve.Params())
	md.Write(bigIntToBytes(pub.Curve, pub.X))
	md.Write(bigIntToBytes(pub.Curve, pub.Y))
	return md.Sum(nil), nil
}

// Sample from Appendix A.2
func TestKeyExchangeRealSample(t *testing.T) {
	initiatorUID := []byte("ALICE123@YAHOO.COM")
	responderUID := []byte("BILL456@YAHOO.COM")
	kenLen := 16

	// initiator's private key
	privA := new(PrivateKey)
	privA.D = bigFromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")
	privA.Curve = sampleParams
	privA.X, privA.Y = privA.Curve.ScalarBaseMult(privA.D.Bytes())
	if hex.EncodeToString(privA.X.Bytes()) != "3099093bf3c137d8fcbbcdf4a2ae50f3b0f216c3122d79425fe03a45dbfe1655" ||
		hex.EncodeToString(privA.Y.Bytes()) != "3df79e8dac1cf0ecbaa2f2b49d51a4b387f2efaf482339086a27a8e05baed98b" {
		t.Fatalf("unexpected public key PA")
	}

	// initiator's Z value
	za, _ := calculateSampleZA(&privA.PublicKey, sampleParams.A, initiatorUID)
	if hex.EncodeToString(za) != "e4d1d0c3ca4c7f11bc8ff8cb3f4c02a78f108fa098e51a668487240f75e20f31" {
		t.Fatalf("unexpected ZA")
	}

	// responder's private key
	privB := new(PrivateKey)
	privB.D = bigFromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")
	privB.Curve = sampleParams
	privB.X, privB.Y = privB.Curve.ScalarBaseMult(privB.D.Bytes())
	if hex.EncodeToString(privB.X.Bytes()) != "245493d446c38d8cc0f118374690e7df633a8a4bfb3329b5ece604b2b4f37f43" ||
		hex.EncodeToString(privB.Y.Bytes()) != "53c0869f4b9e17773de68fec45e14904e0dea45bf6cecf9918c85ea047c60a4c" {
		t.Fatalf("unexpected public key PB")
	}
	// responder's Z value
	zb, _ := calculateSampleZA(&privB.PublicKey, sampleParams.A, responderUID)
	if hex.EncodeToString(zb) != "6b4b6d0e276691bd4a11bf72f4fb501ae309fdacb72fa6cc336e6656119abd67" {
		t.Fatalf("unexpected ZB")
	}

	// create initiator
	initiator, err := NewKeyExchange(privA, &privB.PublicKey, initiatorUID, responderUID, kenLen, true)
	if err != nil {
		t.Fatal(err)
	}
	// overwrite Z values, due to different A
	initiator.z = za
	initiator.peerZ = zb

	// create responder
	responder, err := NewKeyExchange(privB, &privA.PublicKey, responderUID, initiatorUID, kenLen, true)
	if err != nil {
		t.Fatal(err)
	}
	// overwrite Z values, due to different A
	responder.z = zb
	responder.peerZ = za

	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()

	// for initiator's step A1-A3
	rA := bigFromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")
	initKeyExchange(initiator, rA)
	if hex.EncodeToString(initiator.secret.X.Bytes()) != "6cb5633816f4dd560b1dec458310cbcc6856c09505324a6d23150c408f162bf0" ||
		hex.EncodeToString(initiator.secret.Y.Bytes()) != "0d6fcf62f1036c0a1b6daccf57399223a65f7d7bf2d9637e5bbbeb857961bf1a" {
		t.Fatalf("unexpected RA")
	}

	// for responder's step B1-B8
	rB := bigFromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")
	RB, sB, _ := respondKeyExchange(responder, initiator.secret, rB)
	if hex.EncodeToString(RB.X.Bytes()) != "1799b2a2c778295300d9a2325c686129b8f2b5337b3dcf4514e8bbc19d900ee5" ||
		hex.EncodeToString(RB.Y.Bytes()) != "54c9288c82733efdf7808ae7f27d0e732f7c73a7d9ac98b7d8740a91d0db3cf4" {
		t.Fatalf("unexpected RB")
	}
	if hex.EncodeToString(sB) != "284c8f198f141b502e81250f1581c7e9eeb4ca6990f9e02df388b45471f5bc5c" {
		t.Fatalf("unexpected sB")
	}

	// for initiator's step A4-A10
	keyA, sA, err := initiator.ConfirmResponder(RB, sB)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sA) != "23444daf8ed7534366cb901c84b3bdbb63504f4065c1116c91a4c00697e6cf7a" {
		t.Fatalf("unexpected sA")
	}

	// for responder's step B10
	keyB, err := responder.ConfirmInitiator(sA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Errorf("got different key")
	}
	if !bytes.Equal(keyA, hexDecode(t, "55B0AC62A6B927BA23703832C853DED4")) {
		t.Errorf("got unexpected keying data %v\n", hex.EncodeToString(keyA))
	}
}
