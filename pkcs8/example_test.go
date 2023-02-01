package pkcs8_test

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/emmansun/gmsm/pkcs8"
	"github.com/emmansun/gmsm/sm2"
)

func ExampleMarshalPrivateKey_withoutPassword() {
	// real private key should be from secret storage, or generate directly
	privKey, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	d := new(big.Int).SetBytes(privKey)
	testkey := new(sm2.PrivateKey)
	testkey.Curve = sm2.P256()
	testkey.D = d
	testkey.PublicKey.X, testkey.PublicKey.Y = testkey.ScalarBaseMult(testkey.D.Bytes())

	// generate der bytes
	der, err := pkcs8.MarshalPrivateKey(testkey, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from MarshalPrivateKey: %s\n", err)
		return
	}

	// ecode to pem
	block := &pem.Block{Bytes: der, Type: "PRIVATE KEY"}
	pemContent := string(pem.EncodeToMemory(block))
	fmt.Printf("%v\n", pemContent)
}

func ExampleParsePrivateKey_withoutPassword() {
	const privateKeyPem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgbFoKCy7tPL7D5PEl
K/4OKMUEoca/GZnuuwr57w+ObIWhRANCAASDVuZCpA69GNKbo1MvvZ87vujwJ8P2
85pbovhwNp+ZiJgfXv5V0cXN9sDvKwcIR6FPf99CcqjfCcRC8wWK+Uuh
-----END PRIVATE KEY-----`
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		fmt.Fprintf(os.Stderr, "Failed to parse PEM block\n")
		return
	}
	pk, params, err := pkcs8.ParsePrivateKey(block.Bytes, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from ParsePrivateKey: %s\n", err)
		return
	}
	if params == nil && pk != nil {
		fmt.Println("ok")
	} else {
		fmt.Println("fail")
	}
	// Output: ok
}

func ExampleParsePKCS8PrivateKey_withoutPassword() {
	const privateKeyPem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgbFoKCy7tPL7D5PEl
K/4OKMUEoca/GZnuuwr57w+ObIWhRANCAASDVuZCpA69GNKbo1MvvZ87vujwJ8P2
85pbovhwNp+ZiJgfXv5V0cXN9sDvKwcIR6FPf99CcqjfCcRC8wWK+Uuh
-----END PRIVATE KEY-----`
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		fmt.Fprintf(os.Stderr, "Failed to parse PEM block\n")
		return
	}
	pk, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from ParsePKCS8PrivateKey: %s\n", err)
		return
	}
	if pk != nil {
		fmt.Println("ok")
	} else {
		fmt.Println("fail")
	}
	// Output: ok
}

func ExampleParsePKCS8PrivateKeySM2_withoutPassword() {
	const privateKeyPem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgbFoKCy7tPL7D5PEl
K/4OKMUEoca/GZnuuwr57w+ObIWhRANCAASDVuZCpA69GNKbo1MvvZ87vujwJ8P2
85pbovhwNp+ZiJgfXv5V0cXN9sDvKwcIR6FPf99CcqjfCcRC8wWK+Uuh
-----END PRIVATE KEY-----`
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		fmt.Fprintf(os.Stderr, "Failed to parse PEM block\n")
		return
	}
	pk, err := pkcs8.ParsePKCS8PrivateKeySM2(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from ParsePKCS8PrivateKeySM2: %s\n", err)
		return
	}
	if pk != nil {
		fmt.Println("ok")
	} else {
		fmt.Println("fail")
	}
	// Output: ok
}

func ExampleMarshalPrivateKey() {
	// real private key should be from secret storage, or generate directly
	privKey, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	d := new(big.Int).SetBytes(privKey)
	testkey := new(sm2.PrivateKey)
	testkey.Curve = sm2.P256()
	testkey.D = d
	testkey.PublicKey.X, testkey.PublicKey.Y = testkey.ScalarBaseMult(testkey.D.Bytes())

	password := []byte("Password1")
	opts := &pkcs8.Opts{
		Cipher: pkcs8.SM4CBC,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize: 16, IterationCount: 16, HMACHash: pkcs8.SM3,
		},
	}
	// generate der bytes
	der, err := pkcs8.MarshalPrivateKey(testkey, password, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from MarshalPrivateKey: %s\n", err)
		return
	}

	// ecode to pem
	block := &pem.Block{Bytes: der, Type: "ENCRYPTED PRIVATE KEY"}
	pemContent := string(pem.EncodeToMemory(block))
	fmt.Printf("%v\n", pemContent)
}

func ExampleParsePrivateKey() {
	const privateKeyPem = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH2MGEGCSqGSIb3DQEFDTBUMDQGCSqGSIb3DQEFDDAnBBDa6ckWJNP3QBD7MIF8
4nVqAgEQAgEQMA0GCSqBHM9VAYMRAgUAMBwGCCqBHM9VAWgCBBDMUgr+5Y/XN2g9
mPGiISzGBIGQytwK98/ET4WrS0H7AsUri6FTqztrzAvgzFl3+s9AsaYtUlzE3EzE
x6RWxo8kpKO2yj0a/Jh9WZCD4XAcoZ9aMopiWlOdpXJr/iQlMGdirCYIoF37lHMc
jZHNffmk4ii7NxCfjrzpiFq4clYsNMXeSEnq1tuOEur4kYcjHYSIFc9bPG656a60
+SIJsJuPFi0f
-----END ENCRYPTED PRIVATE KEY-----`
	password := []byte("Password1")

	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		fmt.Fprintf(os.Stderr, "Failed to parse PEM block\n")
		return
	}
	pk, params, err := pkcs8.ParsePrivateKey(block.Bytes, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from ParsePrivateKey: %s\n", err)
		return
	}
	if params != nil && pk != nil {
		fmt.Println("ok")
	} else {
		fmt.Println("fail")
	}
	// Output: ok
}

func ExampleParsePKCS8PrivateKey() {
	const privateKeyPem = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH2MGEGCSqGSIb3DQEFDTBUMDQGCSqGSIb3DQEFDDAnBBDa6ckWJNP3QBD7MIF8
4nVqAgEQAgEQMA0GCSqBHM9VAYMRAgUAMBwGCCqBHM9VAWgCBBDMUgr+5Y/XN2g9
mPGiISzGBIGQytwK98/ET4WrS0H7AsUri6FTqztrzAvgzFl3+s9AsaYtUlzE3EzE
x6RWxo8kpKO2yj0a/Jh9WZCD4XAcoZ9aMopiWlOdpXJr/iQlMGdirCYIoF37lHMc
jZHNffmk4ii7NxCfjrzpiFq4clYsNMXeSEnq1tuOEur4kYcjHYSIFc9bPG656a60
+SIJsJuPFi0f
-----END ENCRYPTED PRIVATE KEY-----`
	password := []byte("Password1")
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		fmt.Fprintf(os.Stderr, "Failed to parse PEM block\n")
		return
	}
	pk, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from ParsePKCS8PrivateKey: %s\n", err)
		return
	}
	if pk != nil {
		fmt.Println("ok")
	} else {
		fmt.Println("fail")
	}
	// Output: ok
}

func ExampleParsePKCS8PrivateKeySM2() {
	const privateKeyPem = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH2MGEGCSqGSIb3DQEFDTBUMDQGCSqGSIb3DQEFDDAnBBDa6ckWJNP3QBD7MIF8
4nVqAgEQAgEQMA0GCSqBHM9VAYMRAgUAMBwGCCqBHM9VAWgCBBDMUgr+5Y/XN2g9
mPGiISzGBIGQytwK98/ET4WrS0H7AsUri6FTqztrzAvgzFl3+s9AsaYtUlzE3EzE
x6RWxo8kpKO2yj0a/Jh9WZCD4XAcoZ9aMopiWlOdpXJr/iQlMGdirCYIoF37lHMc
jZHNffmk4ii7NxCfjrzpiFq4clYsNMXeSEnq1tuOEur4kYcjHYSIFc9bPG656a60
+SIJsJuPFi0f
-----END ENCRYPTED PRIVATE KEY-----`
	password := []byte("Password1")
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		fmt.Fprintf(os.Stderr, "Failed to parse PEM block\n")
		return
	}
	pk, err := pkcs8.ParsePKCS8PrivateKeySM2(block.Bytes, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from ParsePKCS8PrivateKeySM2: %s\n", err)
		return
	}
	if pk != nil {
		fmt.Println("ok")
	} else {
		fmt.Println("fail")
	}
	// Output: ok
}
