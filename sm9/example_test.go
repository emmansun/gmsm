package sm9_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/emmansun/gmsm/sm9"
	"golang.org/x/crypto/cryptobyte"
)

func ExampleSignPrivateKey_Sign() {
	// real user sign private key should be from secret storage, e.g. password protected pkcs8 file
	kb, _ := hex.DecodeString("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	var b cryptobyte.Builder
	b.AddASN1BigInt(new(big.Int).SetBytes(kb))
	kb, _ = b.Bytes()
	masterkey, err := sm9.UnmarshalSignMasterPrivateKeyASN1(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalSignMasterPrivateKeyASN1: %s\n", err)
		return
	}
	hid := byte(0x01)
	uid := []byte("Alice")
	userKey, err := masterkey.GenerateUserKey(uid, hid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from GenerateUserKey: %s\n", err)
		return
	}

	// sm9 sign
	hash := []byte("Chinese IBS standard")
	sig, err := userKey.Sign(rand.Reader, hash, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from Sign: %s\n", err)
		return
	}

	// Since sign is a randomized function, signature will be
	// different each time.
	fmt.Printf("%x\n", sig)
}

func ExampleVerifyASN1() {
	// get master public key, can be from pem
	keyBytes, _ := hex.DecodeString("03818200049f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c40829dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e3269850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c2541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d")
	masterPubKey, err := sm9.UnmarshalSignMasterPublicKeyASN1(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	hid := byte(0x01)
	uid := []byte("Alice")
	hash := []byte("Chinese IBS standard")
	sig, _ := hex.DecodeString("30660420b0d0c0bb1b57ea0d5b51cb5c96be850b8c2eef6b0fff5fcccb524b972574e6eb03420004901819575c9211c7b4e6e137794d23d0095608bcdad5c82dbff05777c5b49c763e4425acea2aaedf9e48d4784b4e4a5621cc3663fe0aae44dcbeac183fee9b0f")
	ok := sm9.VerifyASN1(masterPubKey, uid, hid, hash, sig)

	fmt.Printf("%v\n", ok)
	// Output: true
}

func ExampleSignMasterPublicKey_Verify() {
	// get master public key, can be from pem
	masterPubKey := new(sm9.SignMasterPublicKey)
	keyBytes, _ := hex.DecodeString("03818200049f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c40829dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e3269850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c2541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d")
	masterPubKey, err := sm9.UnmarshalSignMasterPublicKeyASN1(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	hid := byte(0x01)
	uid := []byte("Alice")
	hash := []byte("Chinese IBS standard")
	sig, _ := hex.DecodeString("30660420b0d0c0bb1b57ea0d5b51cb5c96be850b8c2eef6b0fff5fcccb524b972574e6eb03420004901819575c9211c7b4e6e137794d23d0095608bcdad5c82dbff05777c5b49c763e4425acea2aaedf9e48d4784b4e4a5621cc3663fe0aae44dcbeac183fee9b0f")
	ok := masterPubKey.Verify(uid, hid, hash, sig)

	fmt.Printf("%v\n", ok)
	// Output: true
}

func ExampleEncryptPrivateKey_UnwrapKey() {
	// real user encrypt private key should be from secret storage, e.g. password protected pkcs8 file
	kb, _ := hex.DecodeString("038182000494736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1")
	userKey, err := sm9.UnmarshalEncryptPrivateKeyASN1(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}

	cipherDer, _ := hex.DecodeString("0342000447689629d1fa57e8def447f42b75e28518a1b692891528ca596f7bcbf581c7cf429ed01b114ce157ed4eadd0b2ded9a7e475e347f67b6affa3a6cf654573f978")
	key, err := userKey.UnwrapKey([]byte("Bob"), cipherDer, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnwrapKey: %s\n", err)
		return
	}
	fmt.Printf("%s\n", hex.EncodeToString(key))
	// Output: 270c42505bca90a8084064ea8af279364405a8195f30664082ead3d6991ed70f
}

func ExampleEncryptMasterPublicKey_WrapKey() {
	// get master public key, can be from pem
	keyBytes, _ := hex.DecodeString("03420004787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1")
	masterPubKey, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	hid := byte(0x03)
	uid := []byte("Bob")
	key, cipherDer, err := masterPubKey.WrapKey(rand.Reader, uid, hid, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from WrapKeyASN1: %s\n", err)
		return
	}

	// Since WrapKey is a randomized function, result will be
	// different each time.
	fmt.Printf("%s %s\n", hex.EncodeToString(key), hex.EncodeToString(cipherDer))
}

func ExampleEncryptPrivateKey_Decrypt() {
	// real user encrypt private key should be from secret storage, e.g. password protected pkcs8 file
	kb, _ := hex.DecodeString("038182000494736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1")
	userKey, err := sm9.UnmarshalEncryptPrivateKeyASN1(kb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	uid := []byte("Bob")
	cipherDer, _ := hex.DecodeString("307f020100034200042cb3e90b0977211597652f26ee4abbe275ccb18dd7f431876ab5d40cc2fc563d9417791c75bc8909336a4e6562450836cc863f51002e31ecf0c4aae8d98641070420638ca5bfb35d25cff7cbd684f3ed75f2d919da86a921a2e3e2e2f4cbcf583f240414b7e776811774722a8720752fb1355ce45dc3d0df")
	plaintext, err := userKey.DecryptASN1(uid, cipherDer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from Decrypt: %s\n", err)
		return
	}
	fmt.Printf("%s\n", plaintext)
	// Output: Chinese IBE standard
}

func ExampleEncryptMasterPublicKey_Encrypt() {
	// get master public key, can be from pem
	keyBytes, _ := hex.DecodeString("03420004787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1")
	masterPubKey, err := sm9.UnmarshalEncryptMasterPublicKeyASN1(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from UnmarshalASN1: %s\n", err)
		return
	}
	hid := byte(0x03)
	uid := []byte("Bob")

	ciphertext, err := masterPubKey.Encrypt(rand.Reader, uid, hid, []byte("Chinese IBE standard"), sm9.DefaultEncrypterOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from Encrypt: %s\n", err)
		return
	}
	// Since Encrypt is a randomized function, result will be
	// different each time.
	fmt.Printf("%s\n", hex.EncodeToString(ciphertext))
}
