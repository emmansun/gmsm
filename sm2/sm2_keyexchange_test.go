package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

func TestKeyExchangeSample(t *testing.T) {
	priv1, _ := GenerateKey(rand.Reader)
	priv2, _ := GenerateKey(rand.Reader)
	initiator, err := NewKeyExchange(priv1, &priv2.PublicKey, []byte("Alice"), []byte("Bob"), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewKeyExchange(priv2, &priv1.PublicKey, []byte("Bob"), []byte("Alice"), 32, true)
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
