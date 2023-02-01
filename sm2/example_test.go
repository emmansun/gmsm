package sm2_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/emmansun/gmsm/sm2"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// This example method is just for reference, it's NOT a standard method for key transmission.
// In general, private key will be encoded/formatted with PKCS8, public key will be encoded/formatted with a SubjectPublicKeyInfo structure
// (see RFC 5280, Section 4.1).
func Example_createKeysFromRawValue() {
	key, _ := sm2.GenerateKey(rand.Reader)

	d := new(big.Int).SetBytes(key.D.Bytes()) // here we do NOT check if the d is in (0, N) or not
	// Create private key from *big.Int
	keyCopy := new(sm2.PrivateKey)
	keyCopy.Curve = sm2.P256()
	keyCopy.D = d
	keyCopy.PublicKey.X, keyCopy.PublicKey.Y = keyCopy.ScalarBaseMult(keyCopy.D.Bytes())
	if !key.Equal(keyCopy) {
		log.Fatalf("private key and copy should be equal")
	}
	pointBytes := elliptic.Marshal(key.Curve, key.X, key.Y)
	// Create public key from point (uncompressed)
	publicKeyCopy := new(ecdsa.PublicKey)
	publicKeyCopy.Curve = sm2.P256()
	publicKeyCopy.X, publicKeyCopy.Y = elliptic.Unmarshal(publicKeyCopy.Curve, pointBytes)
	if !key.PublicKey.Equal(publicKeyCopy) {
		log.Fatalf("public key and copy should be equal")
	}
}

// This method provide a sample to handle ASN1 ciphertext ends with extra bytes.
func Example_parseCipherASN1EndsWithInvalidBytes() {
	// a sample method to get frist ASN1 SEQUENCE data
	getFirstASN1Sequence := func(ciphertext []byte) ([]byte, []byte, error) {
		input := cryptobyte.String(ciphertext)
		var inner cryptobyte.String
		if !input.ReadASN1(&inner, asn1.SEQUENCE) {
			return nil, nil, errors.New("there are no sequence tag")
		}
		if len(input) == 0 {
			return ciphertext, nil, nil
		}
		return ciphertext[:len(ciphertext)-len(input)], input, nil
	}

	ciphertext, _ := hex.DecodeString("3081980220298ED52AE2A0EBA8B7567D54DF41C5F9B310EDFA4A8E15ECCB44EDA94F9F1FC20220116BE33B0833C95D8E5FF9483CD2D7EFF7033C92FE5DEAB6197D809FF1EEE05F042097A90979A6FCEBDE883C2E07E9C286818E694EDE37C3CDAA70E4CD481BE883E00430D62160BB179CB20CE3B5ECA0F5A535BEB6E221566C78FEA92105F71BD37F3F850AD2F86F2D1E35F15E9356557DAC026A")
	_, rest, err := getFirstASN1Sequence(ciphertext)
	if err != nil || len(rest) != 0 {
		log.Fatalf("can't get a complete ASN1 sequence")
	}

	ciphertext, _ = hex.DecodeString("3081980220298ED52AE2A0EBA8B7567D54DF41C5F9B310EDFA4A8E15ECCB44EDA94F9F1FC20220116BE33B0833C95D8E5FF9483CD2D7EFF7033C92FE5DEAB6197D809FF1EEE05F042097A90979A6FCEBDE883C2E07E9C286818E694EDE37C3CDAA70E4CD481BE883E00430D62160BB179CB20CE3B5ECA0F5A535BEB6E221566C78FEA92105F71BD37F3F850AD2F86F2D1E35F15E9356557DAC026A0000")
	seq, rest, err := getFirstASN1Sequence(ciphertext)
	if err != nil || len(rest) != 2 {
		log.Fatalf("can't get a complete ASN1 sequence")
	}

	var (
		x1, y1 = &big.Int{}, &big.Int{}
		c2, c3 []byte
		inner  cryptobyte.String
	)

	input := cryptobyte.String(seq)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(x1) ||
		!inner.ReadASN1Integer(y1) ||
		!inner.ReadASN1Bytes(&c3, asn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2, asn1.OCTET_STRING) ||
		!inner.Empty() {
		log.Fatalf("invalid cipher text")
	}
}

// This is a reference method to force SM2 standard with SDK [crypto.Signer].
func ExamplePrivateKey_Sign_forceSM2() {
	toSign := []byte("ShangMi SM2 Sign Standard")
	// real private key should be from secret storage
	privKey, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	d := new(big.Int).SetBytes(privKey)
	testkey := new(sm2.PrivateKey)
	testkey.Curve = sm2.P256()
	testkey.D = d
	testkey.PublicKey.X, testkey.PublicKey.Y = testkey.ScalarBaseMult(testkey.D.Bytes())

	// force SM2 sign standard and use default UID
	sig, err := testkey.Sign(rand.Reader, toSign, sm2.NewSM2SignerOption(true, nil))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from sign: %s\n", err)
		return
	}

	// Since sign is a randomized function, signature will be
	// different each time.
	fmt.Printf("%x\n", sig)
}

func ExampleVerifyASN1WithSM2() {
	// real public key should be from cert or public key pem file
	keypoints, _ := hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	testkey := new(ecdsa.PublicKey)
	testkey.Curve = sm2.P256()
	testkey.X, testkey.Y = elliptic.Unmarshal(testkey.Curve, keypoints)

	toSign := []byte("ShangMi SM2 Sign Standard")
	signature, _ := hex.DecodeString("304402205b3a799bd94c9063120d7286769220af6b0fa127009af3e873c0e8742edc5f890220097968a4c8b040fd548d1456b33f470cabd8456bfea53e8a828f92f6d4bdcd77")

	ok := sm2.VerifyASN1WithSM2(testkey, nil, toSign, signature)

	fmt.Printf("%v\n", ok)
	// Output: true
}

func ExampleEncryptASN1() {
	// real public key should be from cert or public key pem file
	keypoints, _ := hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	testkey := new(ecdsa.PublicKey)
	testkey.Curve = sm2.P256()
	testkey.X, testkey.Y = elliptic.Unmarshal(testkey.Curve, keypoints)

	secretMessage := []byte("send reinforcements, we're going to advance")

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	ciphertext, err := sm2.EncryptASN1(rng, testkey, secretMessage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return
	}
	// Since encryption is a randomized function, ciphertext will be
	// different each time.
	fmt.Printf("Ciphertext: %x\n", ciphertext)
}

func ExamplePrivateKey_Decrypt() {
	ciphertext, _ := hex.DecodeString("308194022100bd31001ce8d39a4a0119ff96d71334cd12d8b75bbc780f5bfc6e1efab535e85a02201839c075ff8bf761dcbe185c9750816410517001d6a130f6ab97fb23337cce150420ea82bd58d6a5394eb468a769ab48b6a26870ca075377eb06663780c920ea5ee0042be22abcf48e56ae9d29ac770d9de0d6b7094a874a2f8d26c26e0b1daaf4ff50a484b88163d04785b04585bb")

	// real private key should be from secret storage
	privKey, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	d := new(big.Int).SetBytes(privKey)
	testkey := new(sm2.PrivateKey)
	testkey.Curve = sm2.P256()
	testkey.D = d
	testkey.PublicKey.X, testkey.PublicKey.Y = testkey.ScalarBaseMult(testkey.D.Bytes())

	plaintext, err := testkey.Decrypt(nil, ciphertext, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		return
	}

	fmt.Printf("Plaintext: %s\n", string(plaintext))
	// Output: Plaintext: send reinforcements, we're going to advance
}
