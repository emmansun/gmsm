package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
)

var vectors = []struct {
	LocalStaticPriv, LocalEphemeralPriv   string
	RemoteStaticPriv, RemoteEphemeralPriv string
	SharedSecret, Key                     string
}{
	{
		"e04c3fd77408b56a648ad439f673511a2ae248def3bab26bdfc9cdbd0ae9607e",
		"6fe0bac5b09d3ab10f724638811c34464790520e4604e71e6cb0e5310623b5b1",
		"7a1136f60d2c5531447e5a3093078c2a505abf74f33aefed927ac0a5b27e7dd7",
		"d0233bdbb0b8a7bfe1aab66132ef06fc4efaedd5d5000692bc21185242a31f6f",
		"046ab5c9709277837cedc515730d04751ef81c71e81e0e52357a98cf41796ab560508da6e858b40c6264f17943037434174284a847f32c4f54104a98af5148d89f",
		"1ad809ebc56ddda532020c352e1e60b121ebeb7b4e632db4dd90a362cf844f8bba85140e30984ddb581199bf5a9dda22",
	},
	{
		"cb5ac204b38d0e5c9fc38a467075986754018f7dbb7cbbc5b4c78d56a88a8ad8",
		"1681a66c02b67fdadfc53cba9b417b9499d0159435c86bb8760c3a03ae157539",
		"4f54b10e0d8e9e2fe5cc79893e37fd0fd990762d1372197ed92dde464b2773ef",
		"a2fe43dea141e9acc88226eaba8908ad17e81376c92102cb8186e8fef61a8700",
		"04677d055355a1dcc9de4df00d3a80b6daa76bdf54ff7e0a3a6359fcd0c6f1e4b4697fffc41bbbcc3a28ea3aa1c6c380d1e92f142233afa4b430d02ab4cebc43b2",
		"7a103ae61a30ed9df573a5febb35a9609cbed5681bcb98a8545351bf7d6824cc4635df5203712ea506e2e3c4ec9b12e7",
	},
	{
		"ee690a34a779ab48227a2f68b062a80f92e26d82835608dd01b7452f1e4fb296",
		"2046c6cee085665e9f3abeba41fd38e17a26c08f2f5e8f0e1007afc0bf6a2a5d",
		"8ef49ea427b13cc31151e1c96ae8a48cb7919063f2d342560fb7eaaffb93d8fe",
		"9baf8d602e43fbae83fedb7368f98c969d378b8a647318f8cafb265296ae37de",
		"04f7e9f1447968b284ff43548fcec3752063ea386b48bfabb9baf2f9c1caa05c2fb12c2cca37326ce27e68f8cc6414c2554895519c28da1ca21e61890d0bc525c4",
		"b18e78e5072f301399dc1f4baf2956c0ed2d5f52f19abb1705131b0865b079031259ee6c629b4faed528bcfa1c5d2cbc",
	},
}

func hexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("invalid hex string:", s)
	}
	return b
}

func TestKeyExchangeSample(t *testing.T) {
	initiatorUID := []byte("Alice")
	responderUID := []byte("Bob")
	kenLen := 48

	for i, v := range vectors {
		priv1 := new(PrivateKey)
		priv1.D, _ = new(big.Int).SetString(v.LocalStaticPriv, 16)
		priv1.Curve = P256()
		priv1.X, priv1.Y = priv1.Curve.ScalarBaseMult(priv1.D.Bytes())

		priv2 := new(PrivateKey)
		priv2.D, _ = new(big.Int).SetString(v.RemoteStaticPriv, 16)
		priv2.Curve = P256()
		priv2.X, priv2.Y = priv1.Curve.ScalarBaseMult(priv2.D.Bytes())

		initiator, err := NewKeyExchange(priv1, &priv2.PublicKey, initiatorUID, responderUID, kenLen, true)
		if err != nil {
			t.Fatal(err)
		}
		responder, err := NewKeyExchange(priv2, &priv1.PublicKey, responderUID, initiatorUID, kenLen, true)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			initiator.Destroy()
			responder.Destroy()
		}()
		rA, _ := new(big.Int).SetString(v.LocalEphemeralPriv, 16)
		initKeyExchange(initiator, rA)

		rB, _ := new(big.Int).SetString(v.RemoteEphemeralPriv, 16)
		RB, s2, _ := respondKeyExchange(responder, initiator.secret, rB)

		key1, s1, err := initiator.ConfirmResponder(RB, s2)
		if err != nil {
			t.Fatal(err)
		}
		key2, err := responder.ConfirmInitiator(s1)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(key1, key2) {
			t.Errorf("got different key")
		}
		if !bytes.Equal(key1, hexDecode(t, v.Key)) {
			t.Errorf("case %v got unexpected keying data", i)
		}
		if !bytes.Equal(elliptic.Marshal(initiator.v.Curve, initiator.v.X, initiator.v.Y), hexDecode(t, v.SharedSecret)) {
			t.Errorf("case %v got unexpected shared key", i)
		}
	}
}

func TestKeyExchange(t *testing.T) {
	priv1, _ := GenerateKey(rand.Reader)
	priv2, _ := GenerateKey(rand.Reader)
	initiator, err := NewKeyExchange(priv1, &priv2.PublicKey, []byte("Alice"), []byte("Bob"), 48, true)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewKeyExchange(priv2, &priv1.PublicKey, []byte("Bob"), []byte("Alice"), 48, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()
	rA, err := initiator.InitKeyExchange(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rB, s2, err := responder.RepondKeyExchange(rand.Reader, rA)
	if err != nil {
		t.Fatal(err)
	}

	key1, s1, err := initiator.ConfirmResponder(rB, s2)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := responder.ConfirmInitiator(s1)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Errorf("got different key")
	}
}

func TestKeyExchangeSimplest(t *testing.T) {
	priv1, _ := GenerateKey(rand.Reader)
	priv2, _ := GenerateKey(rand.Reader)
	initiator, err := NewKeyExchange(priv1, &priv2.PublicKey, nil, nil, 32, false)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewKeyExchange(priv2, &priv1.PublicKey, nil, nil, 32, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()
	rA, err := initiator.InitKeyExchange(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rB, s2, err := responder.RepondKeyExchange(rand.Reader, rA)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2) != 0 {
		t.Errorf("should be no siganature")
	}

	key1, s1, err := initiator.ConfirmResponder(rB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s1) != 0 {
		t.Errorf("should be no siganature")
	}

	key2, err := responder.ConfirmInitiator(nil)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Errorf("got different key")
	}
}

func TestSetPeerParameters(t *testing.T) {
	priv1, _ := GenerateKey(rand.Reader)
	priv2, _ := GenerateKey(rand.Reader)
	priv3, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uidA := []byte("Alice")
	uidB := []byte("Bob")

	initiator, err := NewKeyExchange(priv1, nil, uidA, uidB, 32, true)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewKeyExchange(priv2, nil, uidB, uidA, 32, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()
	rA, err := initiator.InitKeyExchange(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 设置对端参数
	err = initiator.SetPeerParameters(&priv3.PublicKey, uidB)
	if err == nil {
		t.Errorf("should be failed")
	}

	err = initiator.SetPeerParameters(&priv2.PublicKey, uidB)
	if err != nil {
		t.Fatal(err)
	}

	err = responder.SetPeerParameters(&priv1.PublicKey, uidA)
	if err != nil {
		t.Fatal(err)
	}

	rB, s2, err := responder.RepondKeyExchange(rand.Reader, rA)
	if err != nil {
		t.Fatal(err)
	}

	key1, s1, err := initiator.ConfirmResponder(rB, s2)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := responder.ConfirmInitiator(s1)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Errorf("got different key")
	}
}

func TestKeyExchange_SetPeerParameters(t *testing.T) {
	priv1, _ := GenerateKey(rand.Reader)
	priv2, _ := GenerateKey(rand.Reader)
	uidA := []byte("Alice")
	uidB := []byte("Bob")

	initiator, err := NewKeyExchange(priv1, nil, uidA, nil, 32, true)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewKeyExchange(priv2, nil, uidB, nil, 32, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()
	rA, err := initiator.InitKeyExchange(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 设置对端参数
	err = initiator.SetPeerParameters(&priv2.PublicKey, uidB)
	if err != nil {
		t.Fatal(err)
	}
	err = responder.SetPeerParameters(&priv1.PublicKey, uidA)
	if err != nil {
		t.Fatal(err)
	}

	rB, s2, err := responder.RepondKeyExchange(rand.Reader, rA)
	if err != nil {
		t.Fatal(err)
	}

	key1, s1, err := initiator.ConfirmResponder(rB, s2)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := responder.ConfirmInitiator(s1)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Errorf("got different key")
	}
}

func TestKeyExchange_SetPeerParameters_ErrCase(t *testing.T) {
	priv1, _ := GenerateKey(rand.Reader)
	priv2, _ := GenerateKey(rand.Reader)
	uidA := []byte("Alice")
	uidB := []byte("Bob")

	initiator, err := NewKeyExchange(priv1, nil, uidA, nil, 32, true)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewKeyExchange(priv2, &priv1.PublicKey, uidB, uidA, 32, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()
	rA, err := initiator.InitKeyExchange(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rB, s2, err := responder.RepondKeyExchange(rand.Reader, rA)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = initiator.ConfirmResponder(rB, s2)
	if err == nil {
		t.Fatal(errors.New("expect call ConfirmResponder got a error, but not"))
	}

	err = initiator.SetPeerParameters(&priv2.PublicKey, uidB)
	if err != nil {
		t.Fatal(err)
	}

	err = initiator.SetPeerParameters(&priv2.PublicKey, uidB)
	if err == nil {
		t.Fatal(errors.New("expect call SetPeerParameters repeat got a error, but not"))
	}

	err = responder.SetPeerParameters(&priv1.PublicKey, uidA)
	if err == nil {
		t.Fatal(errors.New("expect responder call SetPeerParameters got a error, but not"))
	}
}
