package smx509_test

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"fmt"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func ExampleParsePKIXPublicKey() {
	const pubPEM = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAENpoOih+9ASfmKYx5lK5mLsrUK3Am
B6kLUsqHlVyglXgoMEwo8Sr8xb/Q3gDMNnd7Wyp2bJE9ksb60ansO4QaKg==
-----END PUBLIC KEY-----`

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}

	pub, err := smx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("pub is of type RSA:", pub)
	case *dsa.PublicKey:
		fmt.Println("pub is of type DSA:", pub)
	case *ecdsa.PublicKey:
		fmt.Println("pub is of type ECDSA:", pub.Curve.Params().Name)
	case ed25519.PublicKey:
		fmt.Println("pub is of type Ed25519:", pub)
	default:
		panic("unknown type of public key")
	}
	isSM2 := sm2.IsSM2PublicKey(pub)
	fmt.Printf("%v\n", isSM2)
	// Output:
	// pub is of type ECDSA: sm2p256v1
	// true
}
