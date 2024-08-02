package smx509_test

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"

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

func ExampleParsePKCS8PrivateKey() {
	const privPEM = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgW+2/sIbWJ5bqzQ4D
Vh8sQ2B/6I1PLGIcItXgGxAcdA6hRANCAAQ/Sx9dzxrMJwgoHmQ76X6g4EoM/2ca
Cm0E4OyvrAVYYipqoI2JhFccq9ZYC5cA9cMj9JW0l5fBtSHp3dSd6wNH
-----END PRIVATE KEY-----`
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		panic("failed to parse PEM block containing the private key")
	}
	key, err := smx509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}
	switch priv := key.(type) {
	case *sm2.PrivateKey:
		fmt.Println("priv is of type SM2:", priv.Params().Name)
	default:
		panic("unexpected type of private key")
	}
	// Output:
	// priv is of type SM2: sm2p256v1
}

func ExampleParseTypedECPrivateKey() {
	// Of course, you can remove EC PARAMETERS to make it simple.
	// https://security.stackexchange.com/questions/29778/why-does-openssl-writes-ec-parameters-when-generating-private-key
	const privPEM = `	
-----BEGIN EC PARAMETERS-----
BggqgRzPVQGCLQ==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFvtv7CG1ieW6s0OA1YfLENgf+iNTyxiHCLV4BsQHHQOoAoGCCqBHM9V
AYItoUQDQgAEP0sfXc8azCcIKB5kO+l+oOBKDP9nGgptBODsr6wFWGIqaqCNiYRX
HKvWWAuXAPXDI/SVtJeXwbUh6d3UnesDRw==
-----END EC PRIVATE KEY-----`
	var keyDERBlock *pem.Block
	keyPEMBlock := []byte(privPEM)
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			break
		}
		if keyDERBlock.Type == "EC PARAMETERS" {
			var oid asn1.ObjectIdentifier
			_, err := asn1.Unmarshal(keyDERBlock.Bytes, &oid)
			if err != nil {
				panic("failed to parse private key ecparams")
			}
			fmt.Printf("%v\n", oid)
		}
		if keyDERBlock.Type == "EC PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}
	if keyDERBlock == nil {
		panic("failed to parse PEM block containing the private key")
	}

	key, err := smx509.ParseTypedECPrivateKey(keyDERBlock.Bytes)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}
	switch priv := key.(type) {
	case *sm2.PrivateKey:
		fmt.Println("priv is of type SM2:", priv.Params().Name)
	default:
		panic("unexpected type of private key")
	}
	// Output:
	// 1.2.156.10197.1.301
	// priv is of type SM2: sm2p256v1
}

func ExampleParseSM2PrivateKey() {
	// Of course, you can remove EC PARAMETERS to make it simple.
	// https://security.stackexchange.com/questions/29778/why-does-openssl-writes-ec-parameters-when-generating-private-key
	const privPEM = `	
-----BEGIN EC PARAMETERS-----
BggqgRzPVQGCLQ==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFvtv7CG1ieW6s0OA1YfLENgf+iNTyxiHCLV4BsQHHQOoAoGCCqBHM9V
AYItoUQDQgAEP0sfXc8azCcIKB5kO+l+oOBKDP9nGgptBODsr6wFWGIqaqCNiYRX
HKvWWAuXAPXDI/SVtJeXwbUh6d3UnesDRw==
-----END EC PRIVATE KEY-----`
	var keyDERBlock *pem.Block
	keyPEMBlock := []byte(privPEM)
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			break
		}
		if keyDERBlock.Type == "EC PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}
	if keyDERBlock == nil {
		panic("failed to parse PEM block containing the private key")
	}

	key, err := smx509.ParseSM2PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}
	fmt.Println("priv is of type SM2:", key.Params().Name)
	// Output:
	// priv is of type SM2: sm2p256v1	
}
