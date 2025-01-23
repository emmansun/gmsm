package cfca_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/emmansun/gmsm/cfca"
	"github.com/emmansun/gmsm/sm2"
)

func ExampleParseSM2() {
	base64data := `
MIIDSQIBATBHBgoqgRzPVQYBBAIBBgcqgRzPVQFoBDDkLvKllj9ZWhaKU6MSnxBBV5yaF3tEcOk1
vQniWyVzyaQA4F3j/YvDJwEoE8gOF/swggL5BgoqgRzPVQYBBAIBBIIC6TCCAuUwggKJoAMCAQIC
BRBAmQgJMAwGCCqBHM9VAYN1BQAwXDELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFu
Y2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEbMBkGA1UEAwwSQ0ZDQSBURVNUIFNNMiBPQ0Ex
MB4XDTIwMTExOTA4MzExOFoXDTI1MTExOTA4MzExOFowgYkxCzAJBgNVBAYTAkNOMRcwFQYDVQQK
DA5DRkNBIFRFU1QgT0NBMTENMAsGA1UECwwEUFNCQzEZMBcGA1UECwwQT3JnYW5pemF0aW9uYWwt
MjE3MDUGA1UEAwwuMDUxQOmCruWCqOe6v+S4iuaUtuWNleWVhuaIt0BONTEwMTEzMDAwMTg4NzhA
MTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABJVRC63OKfcL4H324rDOdb4SSlbAjoJDXnK0qmwX
Z59FWmiSqt3ipreljKew4QynjTgR/yfp9yjNgNU8G5pkYdujggEGMIIBAjAfBgNVHSMEGDAWgBRr
/hjaj0I6prhtsy6Igzo0osEw4TAMBgNVHRMBAf8EAjAAMEgGA1UdIARBMD8wPQYIYIEchu8qAQEw
MTAvBggrBgEFBQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xNC5odG0wOQYDVR0f
BDIwMDAuoCygKoYoaHR0cDovL3VjcmwuY2ZjYS5jb20uY24vU00yL2NybDE0MzU2LmNybDAOBgNV
HQ8BAf8EBAMCBsAwHQYDVR0OBBYEFPiGPZT0oTuRXvkyGoOgviNEWnc1MB0GA1UdJQQWMBQGCCsG
AQUFBwMCBggrBgEFBQcDBDAMBggqgRzPVQGDdQUAA0gAMEUCIQCJDSsVPfhr+gnDASMj5Syt+hxs
amHygPecjCLbcdFQQgIgSXC4musF5Fnj/CpNTqvk9+56FuINkATGS8xRh7kzKBE=`
	password := []byte("123456")
	data, err := base64.StdEncoding.DecodeString(base64data)
	if err != nil {
		panic(err)
	}
	priv, cert, err := cfca.ParseSM2(password, data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", priv.D.Bytes())
	fmt.Printf("%v\n", cert.Issuer)
	// Output: d3f24d61bb2816882b8474b778dd7c3166d665f9455dc9d551c989c161e76ab0
	// CN=CFCA TEST SM2 OCA1,O=China Financial Certification Authority,C=CN
}

func ExampleParseSM2_pemEncoded() {
	pemdata := `
-----BEGIN CFCA KEY-----
MIIDSQIBATBHBgoqgRzPVQYBBAIBBgcqgRzPVQFoBDDkLvKllj9ZWhaKU6MSnxBBV5yaF3tEcOk1
vQniWyVzyaQA4F3j/YvDJwEoE8gOF/swggL5BgoqgRzPVQYBBAIBBIIC6TCCAuUwggKJoAMCAQIC
BRBAmQgJMAwGCCqBHM9VAYN1BQAwXDELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFu
Y2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEbMBkGA1UEAwwSQ0ZDQSBURVNUIFNNMiBPQ0Ex
MB4XDTIwMTExOTA4MzExOFoXDTI1MTExOTA4MzExOFowgYkxCzAJBgNVBAYTAkNOMRcwFQYDVQQK
DA5DRkNBIFRFU1QgT0NBMTENMAsGA1UECwwEUFNCQzEZMBcGA1UECwwQT3JnYW5pemF0aW9uYWwt
MjE3MDUGA1UEAwwuMDUxQOmCruWCqOe6v+S4iuaUtuWNleWVhuaIt0BONTEwMTEzMDAwMTg4NzhA
MTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABJVRC63OKfcL4H324rDOdb4SSlbAjoJDXnK0qmwX
Z59FWmiSqt3ipreljKew4QynjTgR/yfp9yjNgNU8G5pkYdujggEGMIIBAjAfBgNVHSMEGDAWgBRr
/hjaj0I6prhtsy6Igzo0osEw4TAMBgNVHRMBAf8EAjAAMEgGA1UdIARBMD8wPQYIYIEchu8qAQEw
MTAvBggrBgEFBQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xNC5odG0wOQYDVR0f
BDIwMDAuoCygKoYoaHR0cDovL3VjcmwuY2ZjYS5jb20uY24vU00yL2NybDE0MzU2LmNybDAOBgNV
HQ8BAf8EBAMCBsAwHQYDVR0OBBYEFPiGPZT0oTuRXvkyGoOgviNEWnc1MB0GA1UdJQQWMBQGCCsG
AQUFBwMCBggrBgEFBQcDBDAMBggqgRzPVQGDdQUAA0gAMEUCIQCJDSsVPfhr+gnDASMj5Syt+hxs
amHygPecjCLbcdFQQgIgSXC4musF5Fnj/CpNTqvk9+56FuINkATGS8xRh7kzKBE=
-----END CFCA KEY-----`
	password := []byte("123456")
	block, _ := pem.Decode([]byte(pemdata))
	if block == nil {
		panic("failed to decode PEM block")
	}
	priv, cert, err := cfca.ParseSM2(password, block.Bytes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", priv.D.Bytes())
	fmt.Printf("%v\n", cert.Issuer)
	// Output: d3f24d61bb2816882b8474b778dd7c3166d665f9455dc9d551c989c161e76ab0
	// CN=CFCA TEST SM2 OCA1,O=China Financial Certification Authority,C=CN
}

func ExampleMarshalSM2_changePassword() {
	pemdata := `
-----BEGIN CFCA KEY-----
MIIDSQIBATBHBgoqgRzPVQYBBAIBBgcqgRzPVQFoBDDkLvKllj9ZWhaKU6MSnxBBV5yaF3tEcOk1
vQniWyVzyaQA4F3j/YvDJwEoE8gOF/swggL5BgoqgRzPVQYBBAIBBIIC6TCCAuUwggKJoAMCAQIC
BRBAmQgJMAwGCCqBHM9VAYN1BQAwXDELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFu
Y2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEbMBkGA1UEAwwSQ0ZDQSBURVNUIFNNMiBPQ0Ex
MB4XDTIwMTExOTA4MzExOFoXDTI1MTExOTA4MzExOFowgYkxCzAJBgNVBAYTAkNOMRcwFQYDVQQK
DA5DRkNBIFRFU1QgT0NBMTENMAsGA1UECwwEUFNCQzEZMBcGA1UECwwQT3JnYW5pemF0aW9uYWwt
MjE3MDUGA1UEAwwuMDUxQOmCruWCqOe6v+S4iuaUtuWNleWVhuaIt0BONTEwMTEzMDAwMTg4NzhA
MTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABJVRC63OKfcL4H324rDOdb4SSlbAjoJDXnK0qmwX
Z59FWmiSqt3ipreljKew4QynjTgR/yfp9yjNgNU8G5pkYdujggEGMIIBAjAfBgNVHSMEGDAWgBRr
/hjaj0I6prhtsy6Igzo0osEw4TAMBgNVHRMBAf8EAjAAMEgGA1UdIARBMD8wPQYIYIEchu8qAQEw
MTAvBggrBgEFBQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xNC5odG0wOQYDVR0f
BDIwMDAuoCygKoYoaHR0cDovL3VjcmwuY2ZjYS5jb20uY24vU00yL2NybDE0MzU2LmNybDAOBgNV
HQ8BAf8EBAMCBsAwHQYDVR0OBBYEFPiGPZT0oTuRXvkyGoOgviNEWnc1MB0GA1UdJQQWMBQGCCsG
AQUFBwMCBggrBgEFBQcDBDAMBggqgRzPVQGDdQUAA0gAMEUCIQCJDSsVPfhr+gnDASMj5Syt+hxs
amHygPecjCLbcdFQQgIgSXC4musF5Fnj/CpNTqvk9+56FuINkATGS8xRh7kzKBE=
-----END CFCA KEY-----`
	password := []byte("123456")
	block, _ := pem.Decode([]byte(pemdata))
	if block == nil {
		panic("failed to decode PEM block")
	}
	priv, cert, err := cfca.ParseSM2(password, block.Bytes)
	if err != nil {
		panic(err)
	}
	newpassword := []byte("654321")
	data, err := cfca.MarshalSM2(newpassword, priv, cert)
	if err != nil {
		panic(err)
	}
	priv2, cert2, err := cfca.ParseSM2(newpassword, data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", priv2.D.Bytes())
	fmt.Printf("%v\n", cert2.Issuer)
	// Output: d3f24d61bb2816882b8474b778dd7c3166d665f9455dc9d551c989c161e76ab0
	// CN=CFCA TEST SM2 OCA1,O=China Financial Certification Authority,C=CN
}

func ExampleCreateCertificateRequest() {
	keyBytes, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	priv, err := sm2.NewPrivateKey(keyBytes)
	if err != nil {
		panic(err)
	}
	random := rand.Reader

	// tmpKey used to decrypt the returned escrow PrivateKey
	keyBytes, _ = hex.DecodeString("cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba")
	tmpKey, err := sm2.NewPrivateKey(keyBytes)
	if err != nil {
		panic(err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "certRequisition",
			Organization: []string{"CFCA TEST CA"},
			Country:      []string{"CN"},
		},
	}
	csrder, err := cfca.CreateCertificateRequest(random, template, priv, &tmpKey.PublicKey, "123456")
	if err != nil {
		panic(err)
	}
	// you can encode the csrder to PEM format or base64 format

	csr, err := cfca.ParseCertificateRequest(csrder)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v\n", csr.Subject)
	fmt.Printf("%v\n", csr.ChallengePassword)
	fmt.Printf("%x\n", csr.TmpPublicKey.(*ecdsa.PublicKey).X)
	// Output: CN=certRequisition,O=CFCA TEST CA,C=CN
	// 123456
	// c7c4d0945ebdfc2111ad64b0e92e04582b0725fea172968c6c40162c810f8882
}

func ExampleParseEscrowPrivateKey() {
	// a sample method to parse the escrow private key
	keydata := `00000000000000010000000000000001000000000000000000000000000000000000000000000268MIHGAgEBBIHArhtKwTVT8dPEkykVRpvQNMxHv/yeqtaKZiSp2MbjcqMZtPfKW8IatiIPPitNhQtU5C7gMbsUxgf5Yo16vDSXdoWqoOOaes2pEJwmXWZI55lMMWc168WgzQ82fmMi05Vhlw9HNjGI3azE6MS5/ujSNGLZ0qAAmLnBiHlXFAXXAWRiy9MxZKwF4xKn6qMaKmkqbYmTbBbEJEhzJBmu0IJ1kNDcTFirAyapghHSw267erSUwsHjkQis9mKYpzGied0E`
	keyBytes, _ := hex.DecodeString("cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba")
	tmpKey, err := sm2.NewPrivateKey(keyBytes)
	if err != nil {
		panic(err)
	}

	encKey, err := cfca.ParseEscrowPrivateKey(tmpKey, []byte(keydata))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", encKey.D.Bytes())
	// Output: f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b
}
