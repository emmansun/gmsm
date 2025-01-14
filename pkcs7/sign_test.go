package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/smx509"
)

func testSign(t *testing.T, isSM bool, content []byte, sigalgs []x509.SignatureAlgorithm) {
	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := smx509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalginter := range sigalgs {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
			}
			var parents []*smx509.Certificate
			parents = append(parents, interCert.Certificate)
			for _, sigalgsigner := range sigalgs {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				for _, testDetach := range []bool{false, true} {
					log.Printf("test %s/%s/%s detached %t\n", sigalgroot, sigalginter, sigalgsigner, testDetach)
					var toBeSigned *SignedData
					if isSM {
						toBeSigned, err = NewSMSignedData(content)
					} else {
						toBeSigned, err = NewSignedData(content)
					}
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot initialize signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}

					// Set the digest to match the end entity cert
					signerDigest, _ := getDigestOIDForSignatureAlgorithm(sigalgsigner)
					toBeSigned.SetDigestAlgorithm(signerDigest)

					if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
						t.Fatalf("test %s/%s/%s: cannot add signer: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						toBeSigned.Detach()
					}
					signed, err := toBeSigned.Finish()
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot finish signing data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
					p7, err := Parse(signed)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot parse signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						// Detached signature should not contain the content
						// So we should not be able to find the content in the parsed data
						// We should suppliment the content to the parsed data before verifying
						p7.Content = content
					}
					if !bytes.Equal(content, p7.Content) {
						t.Errorf("test %s/%s/%s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", sigalgroot, sigalginter, sigalgsigner, content, p7.Content)
					}
					if err := p7.VerifyWithChain(truststore); err != nil {
						t.Errorf("test %s/%s/%s: cannot verify signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if !signerDigest.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
						t.Errorf("test %s/%s/%s: expected digest algorithm %q but got %q",
							sigalgroot, sigalginter, sigalgsigner, signerDigest, p7.Signers[0].DigestAlgorithm.Algorithm)
					}
				}
			}
		}
	}
}

func TestSign(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
		smx509.SM2WithSM3,
	}
	testSign(t, false, content, sigalgs)
}

func TestSignSM(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []x509.SignatureAlgorithm{
		smx509.SM2WithSM3,
	}
	testSign(t, true, content, sigalgs)
}

func ExampleSignedData() {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA256WithRSA, false)
	if err != nil {
		fmt.Printf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		fmt.Printf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestUnmarshalSignedAttribute(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA512WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	testValue := "TestValue"
	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{{Type: oidTest, Value: testValue}},
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	var actual string
	err = p7.UnmarshalSignedAttribute(oidTest, &actual)
	if err != nil {
		t.Fatalf("Cannot unmarshal test value: %s", err)
	}
	if testValue != actual {
		t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
	}
	err = p7.Verify()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSkipCertificates(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA512WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}

	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	if len(p7.Certificates) == 0 {
		t.Errorf("No certificates")
	}

	toBeSigned2, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	if err := toBeSigned2.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{SkipCertificates: true}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err = toBeSigned2.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err = Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	if len(p7.Certificates) > 0 {
		t.Errorf("Have certificates: %v", p7.Certificates)
	}
	// For skip certificates, we should not be able to verify the signature
	// because the signer certificate is not in the chain
	// we should suppliment the signer certificate to the parsed data before verifying
	p7.Certificates = append(p7.Certificates, cert.Certificate)
	err = p7.Verify()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDegenerateCertificate(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA1WithRSA, false)
	if err != nil {
		t.Fatal(err)
	}
	deg, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	testOpenSSLParse(t, deg)
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: deg})
}

// writes the cert to a temporary file and tests that openssl can read it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
	tmpCertFile, err := ioutil.TempFile("", "testCertificate")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCertFile.Name()) // clean up

	if _, err := tmpCertFile.Write(certBytes); err != nil {
		t.Fatal(err)
	}

	opensslCMD := exec.Command("openssl", "pkcs7", "-inform", "der", "-in", tmpCertFile.Name())
	_, err = opensslCMD.Output()
	if err != nil {
		t.Fatal(err)
	}

	if err := tmpCertFile.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSignWithoutAttr(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []struct {
		isSM     bool
		sigAlg   x509.SignatureAlgorithm
		skipCert bool
	}{
		{
			false,
			x509.SHA256WithRSA,
			false,
		},
		{
			true,
			smx509.SM2WithSM3,
			false,
		},
		{
			false,
			x509.SHA256WithRSA,
			true,
		},
		{
			true,
			smx509.SM2WithSM3,
			true,
		},
	}
	for _, sigalg := range sigalgs {
		cert, err := createTestCertificate(sigalg.sigAlg, false)
		if err != nil {
			t.Fatal(err)
		}
		var toBeSigned *SignedData
		if sigalg.isSM {
			toBeSigned, err = NewSMSignedData(content)
		} else {
			toBeSigned, err = NewSignedData(content)
			signerDigest, _ := getDigestOIDForSignatureAlgorithm(sigalg.sigAlg)
			toBeSigned.SetDigestAlgorithm(signerDigest)
		}
		if err != nil {
			t.Fatalf("Cannot initialize signed data: %s", err)
		}
		if err := toBeSigned.SignWithoutAttr(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{SkipCertificates: sigalg.skipCert}); err != nil {
			t.Fatalf("Cannot add signer: %s", err)
		}
		signed, err := toBeSigned.Finish()
		if err != nil {
			t.Fatalf("Cannot finish signing data: %s", err)
		}
		p7, err := Parse(signed)
		if err != nil {
			t.Fatalf("Cannot parse signed data: %v", err)
		}
		if !sigalg.skipCert {
			if len(p7.Certificates) == 0 {
				t.Errorf("No certificates")
			}
			err = p7.Verify()
			if err != nil {
				t.Fatal(err)
			}
		} else {
			if len(p7.Certificates) > 0 {
				t.Errorf("No certificates expected")
			}
			err = p7.Verify()
			if sigalg.skipCert && err.Error() != "pkcs7: No certificate for signer" {
				t.Fatalf("Expected pkcs7: No certificate for signer")
			}
			p7.Certificates = append(p7.Certificates, cert.Certificate)
			err = p7.Verify()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func testSignDigest(t *testing.T, isSM bool, content []byte, sigalgs []x509.SignatureAlgorithm) {
	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := smx509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalginter := range sigalgs {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
			}
			var parents []*smx509.Certificate
			parents = append(parents, interCert.Certificate)
			for _, sigalgsigner := range sigalgs {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				hashOID, err := getDigestOIDForSignatureAlgorithm(sigalgsigner)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot get digest OID: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				hasher, err := getHashForOID(hashOID)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot get hasher: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				var hashInst hash.Hash
				if hasher == crypto.Hash(0) {
					hashInst = sm3.New()
				} else {
					hashInst = hasher.New()
				}
				hashInst.Write(content)
				digest := hashInst.Sum(nil)

				var toBeSigned *SignedData
				if isSM {
					toBeSigned, err = NewSMSignedDataWithDegist(digest)
				} else {
					toBeSigned, err = NewSignedDataWithDegist(digest)
				}
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot initialize signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}

				// Set the digest to match the end entity cert
				signerDigest, _ := getDigestOIDForSignatureAlgorithm(sigalgsigner)
				toBeSigned.SetDigestAlgorithm(signerDigest)

				if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
					t.Fatalf("test %s/%s/%s: cannot add signer: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				signed, err := toBeSigned.Finish()
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot finish signing data: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
				p7, err := Parse(signed)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot parse signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				if len(p7.Content) > 0 {
					t.Errorf("Content should be empty")
				}
				if err := p7.VerifyAsDigestWithChain(truststore); err != nil {
					t.Errorf("test %s/%s/%s: cannot verify signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				if !signerDigest.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
					t.Errorf("test %s/%s/%s: expected digest algorithm %q but got %q",
						sigalgroot, sigalginter, sigalgsigner, signerDigest, p7.Signers[0].DigestAlgorithm.Algorithm)
				}
			}
		}
	}
}

func TestSignWithDigest(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
		smx509.SM2WithSM3,
	}
	testSignDigest(t, false, content, sigalgs)
}

func TestSignSMWithDigest(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []x509.SignatureAlgorithm{
		smx509.SM2WithSM3,
	}
	testSignDigest(t, true, content, sigalgs)
}

func TestSignWithoutAttrWithDigest(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []struct {
		isSM     bool
		sigAlg   x509.SignatureAlgorithm
		skipCert bool
	}{
		{
			false,
			x509.SHA256WithRSA,
			false,
		},
		{
			true,
			smx509.SM2WithSM3,
			false,
		},
		{
			false,
			x509.SHA256WithRSA,
			true,
		},
		{
			true,
			smx509.SM2WithSM3,
			true,
		},
	}
	for _, sigalg := range sigalgs {
		cert, err := createTestCertificate(sigalg.sigAlg, false)
		if err != nil {
			t.Fatal(err)
		}
		hashOID, err := getDigestOIDForSignatureAlgorithm(sigalg.sigAlg)
		if err != nil {
			t.Fatalf("test %s: cannot get digest OID: %s", sigalg.sigAlg, err)
		}
		hasher, err := getHashForOID(hashOID)
		if err != nil {
			t.Fatalf("test %s: cannot get hasher: %s", sigalg.sigAlg, err)
		}
		var digest []byte
		if hasher == crypto.Hash(0) {
			publicKey, ok := cert.Certificate.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("Cannot cast public key to ECDSA public key")
			}
			digest, err = sm2.CalculateSM2Hash(publicKey, content, nil)
			if err != nil {
				t.Fatalf("Cannot calculate SM2 hash: %s", err)
			}
		} else {
			hashInst := hasher.New()
			hashInst.Write(content)
			digest = hashInst.Sum(nil)
		}

		var toBeSigned *SignedData
		if sigalg.isSM {
			toBeSigned, err = NewSMSignedDataWithDegist(digest)
		} else {
			toBeSigned, err = NewSignedDataWithDegist(digest)
			toBeSigned.SetDigestAlgorithm(hashOID)
		}
		if err != nil {
			t.Fatalf("Cannot initialize signed data: %s", err)
		}
		if err := toBeSigned.SignWithoutAttr(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{SkipCertificates: sigalg.skipCert}); err != nil {
			t.Fatalf("Cannot add signer: %s", err)
		}
		signed, err := toBeSigned.Finish()
		if err != nil {
			t.Fatalf("Cannot finish signing data: %s", err)
		}
		p7, err := Parse(signed)
		if err != nil {
			t.Fatalf("Cannot parse signed data: %v", err)
		}
		if len(p7.Content) > 0 {
			t.Errorf("Content should be empty")
		}
		p7.Content = digest
		if !sigalg.skipCert {
			if len(p7.Certificates) == 0 {
				t.Errorf("No certificates")
			}
			err = p7.VerifyAsDigest()
			if err != nil {
				t.Fatal(err)
			}
		} else {
			if len(p7.Certificates) > 0 {
				t.Errorf("No certificates expected")
			}
			err = p7.VerifyAsDigest()
			if sigalg.skipCert && err.Error() != "pkcs7: No certificate for signer" {
				t.Fatalf("Expected pkcs7: No certificate for signer")
			}
			p7.Certificates = append(p7.Certificates, cert.Certificate)
			err = p7.VerifyAsDigest()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
