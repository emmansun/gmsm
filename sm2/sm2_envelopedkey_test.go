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
	key, _ := hex.DecodeString("622dddddf4658c971e6485f1599a814a9aa0161aadcbc4f880d5841ea79561cb")
	sm2Key := new(sm2.PrivateKey)
	sm2Key.D = new(big.Int).SetBytes(key)
	sm2Key.Curve = sm2.P256()
	sm2Key.X, sm2Key.Y = sm2Key.ScalarBaseMult(key)

	invalidASN1, _ := hex.DecodeString("3081ea06082a811ccf550168013079022003858a7ca681c2e7034804d2bcece2d1c200e128ca973f3ad12541b59ec639cd022100bcf5834c775d5d43615abc27d3aeee399985d30942c65cdbe95afc87d96b12860420f84efafe256413fb28af65a57d815cb9a2fc64f754ab29adc1a78e81c433cfe90410fd485762e9c5714a6ee008e76675a14c0441049355f3009f1db15d6a6f751531f3c4741a36a43d1146fc1b0f660314e5fc3b825ed2fda18cb2f624ac6afb370b3755bb267b5747dd8f15836c830b52d4a74d2c04206fd2ef53be43aaa7f0440e96aafd846096f993e254e2a79a9a5b583204487183")
	if _, err := sm2.ParseEnvelopedPrivateKey(sm2Key, invalidASN1); err.Error() != "sm2: invalid asn1 format enveloped key" {
		t.Errorf("expected asn1 error, got %s", err)
	}

	decryptErr, _ := hex.DecodeString("3081ed06082a811ccf55016801307a022100e5ef46b1d4ebd964852e4166d345027625a38e0a17ad41c9febc7bf024f5efc7022100ca5bf589d32f8e9312196fcbb2624442f16e78470ee09dcf770e54eb28a2f3a9042084c55d419c24dbaa5814e9fde8f74e43c0a876a2055f9900ec6d25fd81e1a42104103c6ca06f337cfc666bf59fb02ad1d8d503420004e82a429129f2d73231edcf06f4dad403de94cae7ad565dd3dd511f7d404bef9edcf4e4c856808d797db90bae9ff1f77f6041435ded07b5d783605f5681c17681032100002f5ba3a33feb59e67be3ae4b087bcc42fec46e2d7f15f3b86162ab83965c74")
	if _, err := sm2.ParseEnvelopedPrivateKey(sm2Key, decryptErr); err.Error() != "sm2: decryption error" {
		t.Errorf("expected decrypt error, got %s", err)
	}

	invalidOID, _ := hex.DecodeString("3081ec06082a811ccf550168023079022010cae556013f072ae40873b3e0a4cef6bc841277da233b12f3d8676bb9b0f8a8022100f626c7122e8b7d977d60694bf876433a5a1a9298c109b541d35b928b8eed43550420423c303ec2c8ee14dcea529ffb887c781dcc2e0fc7b77acd1d355d6d344f62700410b9365ed091fde6bbd8152d09fa3a24e10342000445b8fadb3e0f932bfebfead4d686e8b3b7d215d60c4893b18152e3cf35eede1b06e62ca4943bfc8fd47d5651605b808bdde3f701e4d51783485903cfba6cc812032100c9fd8695e09d25c9974ae82f519aa1cdd7b7a7f29c0a5aa8cc93ec6384222fca")
	if _, err := sm2.ParseEnvelopedPrivateKey(sm2Key, invalidOID); err.Error() != "sm2: unsupported symmetric cipher <1.2.156.10197.1.104.2>" {
		t.Errorf("expected invalid oid error, got %s", err)
	}
}
