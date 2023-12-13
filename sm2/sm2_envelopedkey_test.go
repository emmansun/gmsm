package sm2_test

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func TestMarshalEnvelopedPrivateKey(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	tobeEnveloped, _ := sm2.GenerateKey(rand.Reader)

	result, err := sm2.MarshalEnvelopedPrivateKey(rand.Reader, &priv.PublicKey, tobeEnveloped)
	if err != nil {
		t.Fatal(err)
	}
	parsedKey, err := sm2.ParseEnvelopedPrivateKey(priv, result)
	if err != nil {
		t.Fatal(err)
	}
	if !tobeEnveloped.Equal(parsedKey) {
		t.Error("not same key")
	}
}

func TestParseEnvelopedPrivateKey(t *testing.T) {
	key, _ := hex.DecodeString("5cbd96822bb1491ec835ae9c09d4d3825e30bd9955e3c7031fbbe0e72d6fddf6")
	sm2Key := new(sm2.PrivateKey)
	sm2Key.D = new(big.Int).SetBytes(key)
	sm2Key.Curve = sm2.P256()
	sm2Key.X, sm2Key.Y = sm2Key.ScalarBaseMult(key)

	invalidASN1, _ := hex.DecodeString("3081ea06082a811ccf550168013079022003858a7ca681c2e7034804d2bcece2d1c200e128ca973f3ad12541b59ec639cd022100bcf5834c775d5d43615abc27d3aeee399985d30942c65cdbe95afc87d96b12860420f84efafe256413fb28af65a57d815cb9a2fc64f754ab29adc1a78e81c433cfe90410fd485762e9c5714a6ee008e76675a14c0441049355f3009f1db15d6a6f751531f3c4741a36a43d1146fc1b0f660314e5fc3b825ed2fda18cb2f624ac6afb370b3755bb267b5747dd8f15836c830b52d4a74d2c04206fd2ef53be43aaa7f0440e96aafd846096f993e254e2a79a9a5b583204487183")
	if _, err := sm2.ParseEnvelopedPrivateKey(sm2Key, invalidASN1); err.Error() != "sm2: invalid asn1 format enveloped key" {
		t.Errorf("expected asn1 error, got %s", err)
	}

	invalidOID, _ := hex.DecodeString("3081ef300c06082a811ccf55016802050030780220760c5d4eb80f7ec4bb12026586e4badcd41c293b416618575894d9278214aa6c02203fea869801f94f1cf3839e9b666482703c86cef160af8a540daf9c6b9adff5b20420685f05616055daf4948e44d76c366b16745f7a487614c0542d16871baa34be8704104abfcab6cea65caf2c130b222ebe519903420004944a5887f6fad9808516755e81c62f41566dab0f56ca55ad7909880acc051ce157694b11557eba725291166508868e6988c596a30472bef32e03a3dcef6866270321003ec6b59fece00ca37336c12f6d529aa84be07597e315eda1b7b58b0bef2fead9")
	if _, err := sm2.ParseEnvelopedPrivateKey(sm2Key, invalidOID); err.Error() != "sm2: unsupported symmetric cipher <1.2.156.10197.1.104.2>" {
		t.Errorf("expected invalid oid error, got %s", err)
	}

	decryptErr, _ := hex.DecodeString("308183300c06082a811ccf550168010500300c06082a811ccf55016801050003420004cb51edb59a99b3b6bc894f203465bf04045eb8a85f5a14ba7c894aadbba7f7b5093e568351675d4ffd6d90be77ae182656eb98a80289358cd4ad4d65fafec5dc03210074bd8d993eeeb0220a664087b80478c43ddf322dd75e16db1642f5938ca34a0c")
	if _, err := sm2.ParseEnvelopedPrivateKey(sm2Key, decryptErr); err.Error() != "sm2: ciphertext too short" {
		t.Errorf("expected decrypt error, got %s", err)
	}
}
