package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// from https://www.gmcert.org/
var smSignedEvelopedTestData = `-----BEGIN PKCS7-----
MIIDwwYKKoEcz1UGAQQCBKCCA7MwggOvAgEBMYGfMIGcAgEBMAwAAAIIAs64zJDL
T8UwCwYJKoEcz1UBgi0DBHwwegIhAPbXLhqtkA/HeYKgPeZNPP4kT2/PqS7K8NiB
vAFCBsf+AiEA4m9ZyghfFUaE1K4kre9T/R7Td4hVQPij9GOloRykKJ8EIMJ/zBGe
WaqgtCUFu99S3Wovtd6+jN1tDkTJPWgZ6uu1BBCobCvaWMr0Of+Z686i/wVrMQww
CgYIKoEcz1UBgxEwWQYKKoEcz1UGAQQCATAJBgcqgRzPVQFogEDM1pUC/MDTCRCQ
uZiIxZYZzNaVAvzA0wkQkLmYiMWWGUnT7MvXe2M2khckxgU+ZMVBNDpf4EFl6+C2
PRPcy8ROoIIB4jCCAd4wggGDoAMCAQICCALODAD8KSAXMAoGCCqBHM9VAYN1MEIx
CzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njER
MA8GA1UECgwI5rWL6K+VQ0EwHhcNMjExMjIzMDg0ODMzWhcNMzExMjIzMDg0ODMz
WjBCMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG5rWZ5rGfMQ8wDQYDVQQHDAbmna3l
t54xETAPBgNVBAoMCOa1i+ivlUNBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
SrOgeWQcu+dzrGUniH7/M0nG4ol5C4wfj5cPmFr6HrEZKmBnvzKo6/K65k4auohF
rm2CumYkEFeeJCpXL2tx7aNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFDaT4xTnRQn61e/qLxIt06GWPMKkMB8GA1UdIwQYMBaA
FDaT4xTnRQn61e/qLxIt06GWPMKkMAoGCCqBHM9VAYN1A0kAMEYCIQCw4bSylc4l
IV203nQ6L0QDUgnbugidDAMO1m5d7wFhjgIhAMwly3Bd9gzOQM3vTKqVH0H2D2kU
y2JDcEl5cPy1GBOhMYG4MIG1AgEBME4wQjELMAkGA1UEBhMCQ04xDzANBgNVBAgM
Bua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjmtYvor5VDQQIIAs4M
APwpIBcwCgYIKoEcz1UBgxEwCwYJKoEcz1UBgi0BBEcwRQIgR7STVlgH/yy4k93+
h3KRFN+dWEVeOJ7G1lRRSNXihnkCIQCHxZvmdUcv38SBCgZp+qxnpm2a+C1/tWKV
d/A8tW8dnw==
-----END PKCS7-----
`

var encCert = `-----BEGIN CERTIFICATE-----
MIICPTCCAeOgAwIBAgIIAs64zJDLT8UwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMzAyMjIxMjIwMzNaFw0yNDAyMjIxMjIwMzNaMH0xCzAJBgNV
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEVMBMGA1UE
CgwM5rWL6K+V5py65p6EMRUwEwYDVQQLDAzmtYvor5Xnu4Tnu4cxHjAcBgNVBAMM
Fea1i+ivleacjeWKoeWZqOWQjeensDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA
BGqelO/A74LrAZvxFopkSz9lpjygTF1ffslhB0BzwxQ5jMx1D4912Swb6foMe+0k
bq9V2i3Kn2HrzSTAcj+G+9ujgYcwgYQwDgYDVR0PAQH/BAQDAgM4MBMGA1UdJQQM
MAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDd41c6+e9aahmQD
PdC8YSXfwYgUMB8GA1UdIwQYMBaAFDaT4xTnRQn61e/qLxIt06GWPMKkMA8GA1Ud
EQQIMAaHBH8AAAEwCgYIKoEcz1UBg3UDSAAwRQIgMZBhweovXaHVNSlLv0rTEYnT
GRSsTKmrkCDrxQdaWVUCIQCqeAiXqEnwcdOb6DTFxKF2E2htppt7H4y1K8UVmF7s
eg==
-----END CERTIFICATE-----
`

var signCert = `-----BEGIN CERTIFICATE-----
MIICPTCCAeOgAwIBAgIIAs64zJDLTNQwCgYIKoEcz1UBg3UwQjELMAkGA1UEBhMC
Q04xDzANBgNVBAgMBua1meaxnzEPMA0GA1UEBwwG5p2t5beeMREwDwYDVQQKDAjm
tYvor5VDQTAeFw0yMzAyMjIxMjIwMzNaFw0yNDAyMjIxMjIwMzNaMH0xCzAJBgNV
BAYTAkNOMQ8wDQYDVQQIDAbmtZnmsZ8xDzANBgNVBAcMBuadreW3njEVMBMGA1UE
CgwM5rWL6K+V5py65p6EMRUwEwYDVQQLDAzmtYvor5Xnu4Tnu4cxHjAcBgNVBAMM
Fea1i+ivleacjeWKoeWZqOWQjeensDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA
BL4bEPQAKg3aEjsXsnEm4tSFOetUMYzUpLJyYKc0isNwiu8fNBZAihjDOVzQ3FQf
BeZXJdxvbdC5s22m1E81mwSjgYcwgYQwDgYDVR0PAQH/BAQDAgbAMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBGRF+xJjaBurdse
flfRaPUcBjFWMB8GA1UdIwQYMBaAFDaT4xTnRQn61e/qLxIt06GWPMKkMA8GA1Ud
EQQIMAaHBH8AAAEwCgYIKoEcz1UBg3UDSAAwRQIhAKfa/H/f2OgTXhipfEPXPiHb
nZFJyugnvKFkrijK8Qp5AiARlYEA2FR21H43/e/qu2lrp+ZUeYk3ve8nMd3yua9L
Ag==
-----END CERTIFICATE-----
`

var signKey = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg1FlRx/WjmIFZ5dV4
ghl1JwHIfMdGKLvYdPd1akXUCQSgCgYIKoEcz1UBgi2hRANCAAS+GxD0ACoN2hI7
F7JxJuLUhTnrVDGM1KSycmCnNIrDcIrvHzQWQIoYwzlc0NxUHwXmVyXcb23QubNt
ptRPNZsE
-----END PRIVATE KEY-----
`

var expectedEncKey = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgyhwdf0K3AnMCLEbG
B1yMjJLLlfQkGE53dvCPttt1BkCgCgYIKoEcz1UBgi2hRANCAARqnpTvwO+C6wGb
8RaKZEs/ZaY8oExdX37JYQdAc8MUOYzMdQ+PddksG+n6DHvtJG6vVdotyp9h680k
wHI/hvvb
-----END PRIVATE KEY-----
`

func TestParseSignedEvnvelopedData(t *testing.T) {
	var block *pem.Block
	block, rest := pem.Decode([]byte(smSignedEvelopedTestData))
	if len(rest) != 0 {
		t.Fatal("unexpected remaining PEM block during decode")
	}
	p7Data, err := Parse(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(p7Data.Certificates) != 1 {
		t.Fatal("should only one certificate")
	}

	recipients, err := p7Data.GetRecipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 {
		t.Fatal("should only one recipient")
	}

	block, rest = pem.Decode([]byte(signKey))
	if len(rest) != 0 {
		t.Fatal("unexpected remaining PEM block during decode")
	}
	signPriv, err := smx509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sm2SignPriv, ok := signPriv.(*sm2.PrivateKey)
	if !ok {
		t.Fatal("not expected key type")
	}

	signCertificate, err := smx509.ParseCertificatePEM([]byte(signCert))
	if err != nil {
		t.Fatal(err)
	}

	if !sm2SignPriv.PublicKey.Equal(signCertificate.PublicKey) {
		t.Fatal("not one key pair")
	}

	encKeyBytes, err := p7Data.DecryptAndVerifyOnlyOne(signPriv, func() error {
		return p7Data.Verify()
	})
	if err != nil {
		t.Fatal(err)
	}

	block, rest = pem.Decode([]byte(expectedEncKey))
	if len(rest) != 0 {
		t.Fatal("unexpected remaining PEM block during decode")
	}
	encPriv, err := smx509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sm2EncPriv, ok := encPriv.(*sm2.PrivateKey)
	if !ok {
		t.Fatal("not expected key type")
	}
	if new(big.Int).SetBytes(encKeyBytes).Cmp(sm2EncPriv.D) != 0 {
		t.Fatalf("the priv key is not same, got %x, expected %x", encKeyBytes, sm2EncPriv.D.Bytes())
	}
}

func TestCreateSignedEvnvelopedDataSM(t *testing.T) {
	rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, smx509.SM2WithSM3, true)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := createTestCertificateByIssuer("PKCS7 Test Recipient", rootCert, smx509.SM2WithSM3, false)
	if err != nil {
		t.Fatal(err)
	}
	encryptKey, err := createTestCertificateByIssuer("PKCS7 Test Encrypt Key", rootCert, smx509.SM2WithSM3, false)
	if err != nil {
		t.Fatal(err)
	}
	privKey := make([]byte, 32)
	sm2Key, ok := (*encryptKey.PrivateKey).(*sm2.PrivateKey)
	if !ok {
		t.Fatal("should be sm2 private key")
	}
	sm2Key.D.FillBytes(privKey)

	rootSM2Priv, ok := (*rootCert.PrivateKey).(*sm2.PrivateKey)
	if !ok {
		t.Fatal("should be sm2 private key")
	}
	signKeys := []crypto.PrivateKey{rootSM2Priv, &rootSM2Priv.PrivateKey}
	testCipers := []pkcs.Cipher{pkcs.SM4ECB, pkcs.SM4CBC, pkcs.SM4GCM}
	for _, key := range signKeys {
		for _, cipher := range testCipers {
			saed, err := NewSMSignedAndEnvelopedData(privKey, cipher)
			if err != nil {
				t.Fatal(err)
			}
			err = saed.AddSigner(rootCert.Certificate, key)
			if err != nil {
				t.Fatal(err)
			}
			err = saed.AddRecipient(recipient.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			result, err := saed.Finish()
			if err != nil {
				t.Fatal(err)
			}

			// fmt.Printf("%x\n", result)

			// parse, decrypt, verify
			p7Data, err := Parse(result)
			if err != nil {
				t.Fatal(err)
			}
			encKeyBytes, err := p7Data.DecryptAndVerify(recipient.Certificate, *recipient.PrivateKey, func() error {
				return p7Data.Verify()
			})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encKeyBytes, privKey) {
				t.Fatal("not same private key")
			}
		}
	}
}

func TestCreateSignedEvnvelopedData(t *testing.T) {
	rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, smx509.ECDSAWithSHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := createTestCertificateByIssuer("PKCS7 Test Recipient", rootCert, smx509.SHA256WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	unsupportRecipient, err := createTestCertificateByIssuer("PKCS7 Test Unsupport Recipient", rootCert, smx509.ECDSAWithSHA256, false)
	if err != nil {
		t.Fatal(err)
	}

	encryptKey, err := createTestCertificateByIssuer("PKCS7 Test Encrypt Key", rootCert, smx509.ECDSAWithSHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	privKey := make([]byte, 32)
	ecdsaKey, ok := (*encryptKey.PrivateKey).(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("should be ecdsa private key")
	}
	ecdsaKey.D.FillBytes(privKey)

	testCipers := []pkcs.Cipher{pkcs.AES256CBC, pkcs.AES256GCM}
	for _, cipher := range testCipers {
		saed, err := NewSignedAndEnvelopedData(privKey, cipher)
		if err != nil {
			t.Fatal(err)
		}
		saed.SetDigestAlgorithm(OIDDigestAlgorithmSHA256)
		err = saed.AddSigner(rootCert.Certificate, *rootCert.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		err = saed.AddRecipient(recipient.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		if err = saed.AddRecipient(unsupportRecipient.Certificate); err.Error() != "pkcs7: only supports RSA/SM2 key" {
			t.Fatal("not expected error message")
		}

		result, err := saed.Finish()
		if err != nil {
			t.Fatal(err)
		}

		// fmt.Printf("%x\n", result)

		// parse, decrypt, verify
		p7Data, err := Parse(result)
		if err != nil {
			t.Fatal(err)
		}

		recipients, err := p7Data.GetRecipients()
		if err != nil {
			t.Fatal(err)
		}
		if len(recipients) != 1 {
			t.Fatal("should only one recipient")
		}

		if recipients[0].SerialNumber.Cmp(recipient.Certificate.SerialNumber) != 0 {
			t.Errorf("Recipient serial number does not match.\n\tExpected:%s\n\tActual:%s", recipient.Certificate.SerialNumber, recipients[0].SerialNumber)
		}

		if !bytes.Equal(recipients[0].RawIssuer, recipient.Certificate.RawIssuer) {
			t.Errorf("Recipient issuer name does not match.\n\tExpected:%x\n\tActual:%x", recipient.Certificate.RawIssuer, recipients[0].RawIssuer)
		}

		encKeyBytes, err := p7Data.DecryptAndVerify(recipient.Certificate, *recipient.PrivateKey, func() error {
			return p7Data.Verify()
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encKeyBytes, privKey) {
			t.Fatal("not same private key")
		}
	}
}
