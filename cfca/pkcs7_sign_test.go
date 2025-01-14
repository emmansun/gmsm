// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"crypto/ecdsa"
	"encoding/base64"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func TestSignMessageAttach(t *testing.T) {
	_, err := SignMessageAttach(nil, nil, nil)
	if err == nil {
		t.Fatalf("SignMessageAttach() error = %v, wantErr %v", err, true)
	}
	pair, err := createTestSM2Certificate(false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignMessageAttach([]byte("test"), pair.Certificate, nil)
	if err == nil {
		t.Fatalf("SignMessageAttach() error = %v, wantErr %v", err, true)
	}
	p7, err := SignMessageAttach([]byte("test"), pair.Certificate, pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	p7[0] = 0x20
	err = VerifyMessageAttach(p7)
	if err == nil {
		t.Fatalf("VerifyMessageAttach() error = %v, wantErr %v", err, true)
	}
	p7[0] = 0x30
	err = VerifyMessageAttach(p7)
	if err != nil {
		t.Fatal(err)
	}

	p7, _ = base64.StdEncoding.DecodeString(sadkSignedData)
	err = VerifyMessageAttach(p7)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignMessageDetach(t *testing.T) {
	_, err := SignMessageDetach(nil, nil, nil)
	if err == nil {
		t.Fatalf("SignMessageAttach() error = %v, wantErr %v", err, true)
	}
	pair, err := createTestSM2Certificate(false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignMessageDetach([]byte("test"), pair.Certificate, nil)
	if err == nil {
		t.Fatalf("SignMessageAttach() error = %v, wantErr %v", err, true)
	}
	p7, err := SignMessageDetach([]byte("test"), pair.Certificate, pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	p7[0] = 0x20
	err = VerifyMessageDetach(p7, []byte("test"))
	if err == nil {
		t.Fatalf("VerifyMessageAttach() error = %v, wantErr %v", err, true)
	}
	p7[0] = 0x30
	err = VerifyMessageDetach(p7, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyMessageDetach(p7, []byte("test 1"))
	if err == nil || err.Error() != "x509: SM2 verification failure" {
		t.Fatalf("VerifyMessageAttach() error = %v, wantErr %v", err, true)
	}
	err = VerifyMessageDetach(p7, nil)
	if err == nil || err.Error() != "x509: SM2 verification failure" {
		t.Fatalf("VerifyMessageAttach() error = %v, wantErr %v", err, true)
	}

	p7, _ = base64.StdEncoding.DecodeString(sadkSignedDataDetach)
	err = VerifyMessageDetach(p7, []byte("Hello Secret World!"))
	if err != nil {
		t.Fatal(err)
	}
}

var sadkSignedData = "MIICgAYKKoEcz1UGAQQCAqCCAnAwggJsAgEBMQ4wDAYIKoEcz1UBgxEFADAjBgoqgRzPVQYBBAIBoBUEE0hlbGxvIFNlY3JldCBXb3JsZCGgggGNMIIBiTCCAS+gAwIBAgIFAKncGpAwCgYIKoEcz1UBg3UwKTEQMA4GA1UEChMHQWNtZSBDbzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrMB4XDTI0MTExOTAwMTIyNVoXDTI1MTExOTAwMTIyNlowJTEQMA4GA1UEChMHQWNtZSBDbzERMA8GA1UEAxMISm9uIFNub3cwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATYcgrHXJmFO1/t/9WQ6GkCW6D0yDyd2ya5wRXjVAU08I9Oo6k99jB2MPauCn64W81APRCPHLlwWOtuIsmSmQhjo0gwRjAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwQwHwYDVR0jBBgwFoAUyBfYaeGJxaf9ST9aCRgotC+MwvwwCgYIKoEcz1UBg3UDSAAwRQIgRaF0PA74cCYKeu8pZ4VDQti+rE283Hq/tGXzXUzOWKUCIQDl3z1boZxtRscbnOGOXg1NY+yoY2lz5b63kGOTkn/SxzGBoDCBnQIBATAyMCkxEDAOBgNVBAoTB0FjbWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyawIFAKncGpAwDAYIKoEcz1UBgxEFADANBgkqgRzPVQGCLQEFAARHMEUCIQCl145xtYc7QWTymATxUGbLfF1mlPlyMoIKSp9alu14UQIgQSV/Ll3yYCyXSNxhPelz8Nsbxopky+Pt56Al54rv3p0="
var sadkSignedDataDetach = "MIICaQYKKoEcz1UGAQQCAqCCAlkwggJVAgEBMQ4wDAYIKoEcz1UBgxEFADAMBgoqgRzPVQYBBAIBoIIBjTCCAYkwggEvoAMCAQICBQCp3BqQMAoGCCqBHM9VAYN1MCkxEDAOBgNVBAoTB0FjbWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyazAeFw0yNDExMTkwMDEyMjVaFw0yNTExMTkwMDEyMjZaMCUxEDAOBgNVBAoTB0FjbWUgQ28xETAPBgNVBAMTCEpvbiBTbm93MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE2HIKx1yZhTtf7f/VkOhpAlug9Mg8ndsmucEV41QFNPCPTqOpPfYwdjD2rgp+uFvNQD0Qjxy5cFjrbiLJkpkIY6NIMEYwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB8GA1UdIwQYMBaAFMgX2GnhicWn/Uk/WgkYKLQvjML8MAoGCCqBHM9VAYN1A0gAMEUCIEWhdDwO+HAmCnrvKWeFQ0LYvqxNvNx6v7Rl811MzlilAiEA5d89W6GcbUbHG5zhjl4NTWPsqGNpc+W+t5Bjk5J/0scxgaAwgZ0CAQEwMjApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmsCBQCp3BqQMAwGCCqBHM9VAYMRBQAwDQYJKoEcz1UBgi0BBQAERzBFAiEA4ylCl8qQDfNDfBw7VkxVN0bUs4N56TZDqZhAdEv01N8CIDtOG5VbmWNZeagC8VRfzEhu+ratFCo3fTu2liV8kH5h"

func TestSignDigestDetach(t *testing.T) {
	_, err := SignDigestDetach(nil, nil, nil)
	if err == nil {
		t.Fatalf("SignDigestDetach() error = %v, wantErr %v", err, true)
	}
	pair, err := createTestSM2Certificate(false)
	if err != nil {
		t.Fatal(err)
	}
	rawMessage := []byte("test")
	digest, err := sm2.CalculateSM2Hash(pair.Certificate.PublicKey.(*ecdsa.PublicKey), rawMessage, nil)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := SignDigestDetach(digest, pair.Certificate, pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyDigestDetach(p7, digest)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyMessageDetach(p7, rawMessage)
	if err != nil {
		t.Fatal(err)
	}
}
