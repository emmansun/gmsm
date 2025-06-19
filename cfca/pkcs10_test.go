// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	certRSAKey, err := rsa.GenerateKey(random, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpKey, err := sm2.GenerateKey(random)
	if err != nil {
		t.Fatal(err)
	}
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(random, 2048)
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

	testCases := []struct {
		template          *x509.CertificateRequest
		priv              interface{}
		tmpPub            interface{}
		challengePassword string
		wantErr           bool
		errormsg          string
	}{
		{
			template:          template,
			priv:              certKey,
			tmpPub:            tmpKey.Public(),
			challengePassword: "111111",
			wantErr:           false,
			errormsg:          "",
		},
		{
			template:          template,
			priv:              certRSAKey,
			tmpPub:            rsaKey.Public(),
			challengePassword: "111111",
			wantErr:           false,
			errormsg:          "",
		},
		{
			template:          template,
			priv:              p256Key,
			tmpPub:            nil,
			challengePassword: "",
			wantErr:           false,
			errormsg:          "",
		},
		{
			template:          template,
			priv:              "",
			tmpPub:            "",
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: certificate private key does not implement crypto.Signer",
		},
		{
			template:          template,
			priv:              certKey,
			tmpPub:            "",
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: SM2 temp public key is required",
		},
		{
			template:          template,
			priv:              certKey,
			tmpPub:            rsaKey.Public(),
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: SM2 temp public key is required",
		},
		{
			template:          template,
			priv:              certRSAKey,
			tmpPub:            tmpKey.Public(),
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: RSA temp public key is required",
		},
		{
			template:          template,
			priv:              certKey,
			tmpPub:            p256Key.Public(),
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: SM2 temp public key is required",
		},
		{
			template:          template,
			priv:              p256Key,
			tmpPub:            certKey.Public(),
			challengePassword: "111111",
			wantErr:           true,
			errormsg:          "x509: only RSA or SM2 key is supported",
		},
		{
			template:          template,
			priv:              certKey,
			tmpPub:            tmpKey.Public(),
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: challenge password is required",
		},
	}
	for _, tc := range testCases {
		_, err := CreateCertificateRequest(random, tc.template, tc.priv, tc.tmpPub, tc.challengePassword)
		if tc.wantErr {
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.errormsg {
				t.Fatalf("expected error %s, got %s", tc.errormsg, err.Error())
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseEscrowPrivateKey(t *testing.T) {
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
		{
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"MIHLAgEBBIHFBNMWBxk04B00wJQC1fQsida/0ZZEAMh/ggaC006oQUFFQKJp18YgC/9xkkBLa75DxPy85+n21gZaXUs3s628SaQiKejqH7yx3Pr0onRepDED5O/grQoyxdHL3LpuC4jp7MrOeVDqC6PAWIhZanDhdN4617QJeBmKbkZSqo/SNXfh9+QDDwBBNMLV27LR53ShpAUYbJwqQoW2Od4+MGkzUK3jy+T9HbPcaAZMedAuhXhQgRf69x8CNSHjmOVVFQQZe7OHYY8=",
			true,
			"cfca: failed to decrypt the private key, possibly due to incorrect key data",
		},
		{
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"MIHKAgEBBIHEMEiAGc8dn+9mKnIlaesNqV2h53FxzNm1O4Bl5P16t6QT4JcJvTcTsh9DiHZF1Z0b+z/PrAT2r8aST2aKwRBPLrkWHKKDLZnCtAuz3Al1sV5ZMb5dCVX/Gy3LWMhVNwmzgkV6hfuFokTc2qL7p297XG4nnT11jz7iI1sRJ2E7bn52tF6W6ApICJuDKyFiLVKmMayn3PSsd8+I5IXNNtIer+GYKabAkNHwao4cuK1tuhy1uiSlwfzWq1CSHFD+LIRbXpijQA==",
			true,
			"cfca: invalid decrypted private key data",
		},
		{
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"MIHGAgEBBIHANZyM9KF7qqyUDzh6wZmLU6czep9FxJfojSpxrAYbNN2j/Jad5cOaNmhO4tL+tfk42O8y9+jUebPWCUOuSXZADJZOEyRo2tehvrT2CxEEA9cJ0pK87uXiRsd9vLyjYeEzbngO8tpFrSrpF8G/KYbJ1QiI3W+QLQnofwtChNVwOjyjLxoFO9gx3jvfVH79ECoYC11UL0o0YASx9niiGkqT/q8tqbr7DwIDu0tbXVfwhjJJ2zNZIdECDkV3o7as9ika",
			true,
			"sm2: invalid private key",
		},
		{
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"MIHGAgEBBIHAaxudEYQXAT4n+s2fhHJlPVvY2+TNRAS96F7vskiENVLHahIWxtDeU6BeJ5SFTEXTz5vdYp4as66DU69xCWNYl4kDCy3gfT2iIDEp6NcbPHkAp/rKIFXMUZyBq9wGCkeAZwvpK09JMLffvGWTFU7MzepyFtYTsRjwZ5tBX+8GaSDHaCD0CtVtz5k3bFRLPE2ru4XZW787BiEBrxUG9Zn5pnkNLlnVmUNSI01qKXJxK/hAJ+B82DtXdZgSUaspW5ro",
			true,
			"point not on SM2 P256 curve",
		},
		{
			"f6e02c941a0dfdac58d8b3b1bc1bd136f179741b7465ebc7b0b25bb381840a3b",
			"cacece36cac24aab94e52bcd5c0f552c95028f2856053135a1e47510b4c307ba",
			"MIHGAgEBBIHA7pcowvNdY6kHesm6Ni1rM+iFNSXOXyET+gstbxQ0Vq1+W+YmZUTNQs8CpNuU6fpjZt8azXvKwdrUKEMaadZR4vTBwl+UcvjdpwlBmI8o9UxYkWNSGeI0CWHCgml57xHbhAl3xlRzCi2qOakvEcwTRmzvB73Pt/DgahSPGSmdOy3CrAyMkhcrHiiR9aIWXEKbOnwST+wcRJ65Mr+5ZDOaN8wg6NzLttnWg93CA3k1AsziCGe/sRW6Qd2FrcvMZQc2",
			true,
			"cfca: key pair mismatch, possibly due to incorrect key data or corruption",
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
		gotKey, err := ParseEscrowPrivateKey(tmpSM2Key, []byte(c.encryptedKey))
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
