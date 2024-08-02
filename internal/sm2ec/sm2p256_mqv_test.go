package sm2ec_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/internal/sm2ec"
)

func randomK(r io.Reader, ord *big.Int) (k *big.Int, err error) {
	for {
		k, err = rand.Int(r, ord)
		if err != nil || (k.Sign() > 0 && len(k.Bytes()) == 32) {
			return
		}
	}
}

func TestImplicitSig(t *testing.T) {
	n, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sPriv, err := randomK(rand.Reader, n)
	if err != nil {
		t.Fatal(err)
	}
	ePriv, err := randomK(rand.Reader, n)
	if err != nil {
		t.Fatal(err)
	}
	k, err := randomK(rand.Reader, n)
	if err != nil {
		t.Fatal(err)
	}
	res1, err := sm2ec.ImplicitSig(sPriv.Bytes(), ePriv.Bytes(), k.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	res2 := new(big.Int)
	res2.Mul(ePriv, k)
	res2.Add(res2, sPriv)
	res2.Mod(res2, n)
	if !bytes.Equal(new(big.Int).SetBytes(res1).Bytes(), res2.Bytes()) {
		t.Errorf("expected %s, got %s", hex.EncodeToString(res1), hex.EncodeToString(res2.Bytes()))
	}
}
