// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func TestCreateCertificateRequest(t *testing.T) {
	random := rand.Reader
	certKey, err := sm2.GenerateKey(random)
	if err != nil {
		t.Fatal(err)
	}
	tmpKey, err := sm2.GenerateKey(random)
	if err != nil {
		t.Fatal(err)
	}
	invalidTmpKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "certRequisition",
			Organization: []string{"CFCA TEST CA"},
			Country:      []string{"CN"},
		},
	}
	_, err = CreateCertificateRequest(random, template, "", "", "")
	if err == nil || err.Error() != "x509: certificate private key does not implement crypto.Signer" {
		t.Fatal("certificate private key does not implement crypto.Signer")
	}
	_, err = CreateCertificateRequest(random, template, certKey, "", "")
	if err == nil || err.Error() != "x509: only SM2 public key is supported" {
		t.Fatal("only SM2 public key is supported")
	}
	_, err = CreateCertificateRequest(random, template, certKey, invalidTmpKey.Public(), "")
	if err == nil || err.Error() != "x509: only SM2 public key is supported" {
		t.Fatal("only SM2 public key is supported")
	}
	_, err = CreateCertificateRequest(random, template, certKey, tmpKey.Public(), "")
	if err == nil || err.Error() != "x509: challenge password is required" {
		t.Fatal("challenge password is required")
	}
	csrDer, err := CreateCertificateRequest(random, template, certKey, tmpKey.Public(), "111111")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCertificateRequest(csrDer)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "certRequisition" {
		t.Fatal("common name not match")
	}
	if csr.Subject.CommonName != "certRequisition" {
		t.Fatal("common name not match")
	}
	if csr.ChallengePassword != "111111" {
		t.Fatal("challenge password not match")
	}
	if csr.TmpPublicKey == nil {
		t.Fatal("tmp public key not match")
	}
}

func TestParseEncryptionPrivateKey(t *testing.T) {
	cases := []struct {
		encKeyHex    string
		tmpKeyHex    string
		encryptedKey string
		wantError    bool
		errorMsg     string
	}{
		{ // with prefix, without delimiter
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"00000000000000010000000000000001000000000000000000000000000000000000000000000268MIHGAgEBBIHArhtKwTVT8dPEkykVRpvQNMxHv/yeqtaKZiSp2MbjcqMZtPfKW8IatiIPPitNhQtU5C7gMbsUxgf5Yo16vDSXdoWqoOOaes2pEJwmXWZI55lMMWc168WgzQ82fmMi05Vhlw9HNjGI3azE6MS5/ujSNGLZ0qAAmLnBiHlXFAXXAWRiy9MxZKwF4xKn6qMaKmkqbYmTbBbEJEhzJBmu0IJ1kNDcTFirAyapghHSw267erSUwsHjkQis9mKYpzGied0E",
			false,
			"",
		},
		{ // without prefix, without delimiter
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"MIHGAgEBBIHArhtKwTVT8dPEkykVRpvQNMxHv/yeqtaKZiSp2MbjcqMZtPfKW8IatiIPPitNhQtU5C7gMbsUxgf5Yo16vDSXdoWqoOOaes2pEJwmXWZI55lMMWc168WgzQ82fmMi05Vhlw9HNjGI3azE6MS5/ujSNGLZ0qAAmLnBiHlXFAXXAWRiy9MxZKwF4xKn6qMaKmkqbYmTbBbEJEhzJBmu0IJ1kNDcTFirAyapghHSw267erSUwsHjkQis9mKYpzGied0E",
			false,
			"",
		},
		{ // with prefix, with delimiter
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"00000000000000010000000000000001000000000000000000000000000000000000000000000273MIHGAgEBBIHArhtKwTVT8dPEkykVRpvQNMxHv/yeqtaKZiSp2MbjcqMZtPfKW8Ia,tiIPPitNhQtU5C7gMbsUxgf5Yo16vDSXdoWqoOOaes2pEJwmXWZI55lMMWc168Wg,zQ82fmMi05Vhlw9HNjGI3azE6MS5/ujSNGLZ0qAAmLnBiHlXFAXXAWRiy9MxZKwF,4xKn6qMaKmkqbYmTbBbEJEhzJBmu0IJ1kNDcTFirAyapghHSw267erSUwsHjkQis,9mKYpzGied0E,",
			false,
			"",
		},
		{ // too short
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"000000000000000100000000000000010",
			true,
			"cfca: invalid encrypted private key data",
		},
		{ // length not match
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"00000000000000010000000000000001000000000000000000000000000000000000000000000273MIHGAgEBBIHArhtKwTVT8dPEkykVRpvQNMxHv/yeqtaKZiSp2MbjcqMZtPfKW8IatiIPPitNhQtU5C7gMbsUxgf5Yo16vDSXdoWqoOOaes2pEJwmXWZI55lMMWc168WgzQ82fmMi05Vhlw9HNjGI3azE6MS5/ujSNGLZ0qAAmLnBiHlXFAXXAWRiy9MxZKwF4xKn6qMaKmkqbYmTbBbEJEhzJBmu0IJ1kNDcTFirAyapghHSw267erSUwsHjkQis9mKYpzGied0E",
			true,
			"cfca: invalid encrypted private key data",
		},
		{ // with prefix, with invalid delimiter
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"00000000000000010000000000000001000000000000000000000000000000000000000000000274MIHGAgEBBIHArhtKwTVT8dPEkykVRpvQNMxHv/yeqtaKZiSp2MbjcqMZtPfKW8Ia, tiIPPitNhQtU5C7gMbsUxgf5Yo16vDSXdoWqoOOaes2pEJwmXWZI55lMMWc168Wg,zQ82fmMi05Vhlw9HNjGI3azE6MS5/ujSNGLZ0qAAmLnBiHlXFAXXAWRiy9MxZKwF,4xKn6qMaKmkqbYmTbBbEJEhzJBmu0IJ1kNDcTFirAyapghHSw267erSUwsHjkQis,9mKYpzGied0E,",
			true,
			"illegal base64 data at input byte 64",
		},
		{ // invalid base64
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"NIHGAgEBBIHArhtKwTVT8dPEkykVRpvQNMxHv/yeqtaKZiSp2MbjcqMZtPfKW8IatiIPPitNhQtU5C7gMbsUxgf5Yo16vDSXdoWqoOOaes2pEJwmXWZI55lMMWc168WgzQ82fmMi05Vhlw9HNjGI3azE6MS5/ujSNGLZ0qAAmLnBiHlXFAXXAWRiy9MxZKwF4xKn6qMaKmkqbYmTbBbEJEhzJBmu0IJ1kNDcTFirAyapghHSw267erSUwsHjkQis9mKYpzGied0E",
			true,
			"asn1: structure error: tags don't match (16 vs {class:0 tag:20 length:198 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} encryptedPrivateKeyInfo @3",
		},
		{ // with prefix, with delimiter, invalid length string
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"00000000000000010000000000000001000000000000000000000000000000000000000000000/73MIHGAgEBBIHArhtKwTVT8dPEkykVRpvQNMxHv/yeqtaKZiSp2MbjcqMZtPfKW8Ia,tiIPPitNhQtU5C7gMbsUxgf5Yo16vDSXdoWqoOOaes2pEJwmXWZI55lMMWc168Wg,zQ82fmMi05Vhlw9HNjGI3azE6MS5/ujSNGLZ0qAAmLnBiHlXFAXXAWRiy9MxZKwF,4xKn6qMaKmkqbYmTbBbEJEhzJBmu0IJ1kNDcTFirAyapghHSw267erSUwsHjkQis,9mKYpzGied0E,",
			true,
			"strconv.Atoi: parsing \"0000000000000/73\": invalid syntax",
		},
	}
	for _, c := range cases {
		encKey, _ := hex.DecodeString(c.encKeyHex)
		tmpKey, _ := hex.DecodeString(c.tmpKeyHex)
		tmpSM2Key, err := sm2.NewPrivateKey(tmpKey)
		if err != nil {
			t.Fatal(err)
		}
		targetEncKey, err := sm2.NewPrivateKey(encKey)
		if err != nil {
			t.Fatal(err)
		}
		gotKey, err := ParseEncryptionPrivateKey(tmpSM2Key, []byte(c.encryptedKey))
		if c.wantError {
			if err == nil || err.Error() != c.errorMsg {
				t.Fatalf("expected error %v, got %v", c.errorMsg, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !gotKey.Equal(targetEncKey) {
			t.Fatalf("decrypted key not match")
		}
	}
}
