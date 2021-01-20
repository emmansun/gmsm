package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"
)

const publicKeyPemFromAliKms = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAELfjZP28bYfGSvbODYlXiB5bcoXE+
2LRjjpIH3DcCCct9FuVhi9cm60nDFrbW49k2D3GJco2iWPlr0+5LV+t4AQ==
-----END PUBLIC KEY-----
`

func getPublicKey(pemContent []byte) (interface{}, error) {
	block, _ := pem.Decode(pemContent)
	if block == nil {
		return nil, errors.New("Failed to parse PEM block")
	}
	return ParsePKIXPublicKey(block.Bytes)
}

func TestParsePKIXPublicKey(t *testing.T) {
	pub, err := getPublicKey([]byte(publicKeyPemFromAliKms))
	if err != nil {
		t.Fatal(err)
	}
	pub1 := pub.(*ecdsa.PublicKey)
	_, err = Encrypt(rand.Reader, pub1, []byte("testfile"))
	if err != nil {
		t.Fatal(err)
	}
}
