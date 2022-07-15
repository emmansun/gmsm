package sm2

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestKeyExchangeSample(t *testing.T) {
	priv1, _ := GenerateKey(rand.Reader)
	priv2, _ := GenerateKey(rand.Reader)
	initiator, err := NewKeyExchange(priv1, &priv2.PublicKey, []byte("Alice"), []byte("Bob"), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	responsder, err := NewKeyExchange(priv2, &priv1.PublicKey, []byte("Bob"), []byte("Alice"), 32, true)
	if err != nil {
		t.Fatal(err)
	}
	rA, err := initiator.InitKeyExchange(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rB, s2, err := responsder.RepondKeyExchange(rand.Reader, rA)
	if err != nil {
		t.Fatal(err)
	}

	s1, err := initiator.ConfirmResponder(rB, s2)
	if err != nil {
		t.Fatal(err)
	}

	err = responsder.ConfirmInitiator(s1)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(initiator.key) != hex.EncodeToString(responsder.key) {
		t.Errorf("got different key")
	}
}
