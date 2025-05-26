package smx509

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"testing"

	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestParseASN1String(t *testing.T) {
	tests := []struct {
		name        string
		tag         cryptobyte_asn1.Tag
		value       []byte
		expected    string
		expectedErr string
	}{
		{
			name:     "T61String",
			tag:      cryptobyte_asn1.T61String,
			value:    []byte{0xbf, 0x61, 0x3f},
			expected: string("¿a?"),
		},
		{
			name:     "PrintableString",
			tag:      cryptobyte_asn1.PrintableString,
			value:    []byte{80, 81, 82},
			expected: string("PQR"),
		},
		{
			name:        "PrintableString (invalid)",
			tag:         cryptobyte_asn1.PrintableString,
			value:       []byte{1, 2, 3},
			expectedErr: "invalid PrintableString",
		},
		{
			name:     "UTF8String",
			tag:      cryptobyte_asn1.UTF8String,
			value:    []byte{80, 81, 82},
			expected: string("PQR"),
		},
		{
			name:        "UTF8String (invalid)",
			tag:         cryptobyte_asn1.UTF8String,
			value:       []byte{255},
			expectedErr: "invalid UTF-8 string",
		},
		{
			name:     "BMPString",
			tag:      cryptobyte_asn1.Tag(asn1.TagBMPString),
			value:    []byte{80, 81},
			expected: string("偑"),
		},
		{
			name:        "BMPString (invalid length)",
			tag:         cryptobyte_asn1.Tag(asn1.TagBMPString),
			value:       []byte{255},
			expectedErr: "invalid BMPString",
		},
		{
			name:        "BMPString (invalid surrogate)",
			tag:         cryptobyte_asn1.Tag(asn1.TagBMPString),
			value:       []byte{80, 81, 216, 1},
			expectedErr: "invalid BMPString",
		},
		{
			name:        "BMPString (invalid noncharacter 0xfdd1)",
			tag:         cryptobyte_asn1.Tag(asn1.TagBMPString),
			value:       []byte{80, 81, 253, 209},
			expectedErr: "invalid BMPString",
		},
		{
			name:        "BMPString (invalid noncharacter 0xffff)",
			tag:         cryptobyte_asn1.Tag(asn1.TagBMPString),
			value:       []byte{80, 81, 255, 255},
			expectedErr: "invalid BMPString",
		},
		{
			name:        "BMPString (invalid noncharacter 0xfffe)",
			tag:         cryptobyte_asn1.Tag(asn1.TagBMPString),
			value:       []byte{80, 81, 255, 254},
			expectedErr: "invalid BMPString",
		},
		{
			name:     "IA5String",
			tag:      cryptobyte_asn1.IA5String,
			value:    []byte{80, 81},
			expected: string("PQ"),
		},
		{
			name:        "IA5String (invalid)",
			tag:         cryptobyte_asn1.IA5String,
			value:       []byte{255},
			expectedErr: "invalid IA5String",
		},
		{
			name:     "NumericString",
			tag:      cryptobyte_asn1.Tag(asn1.TagNumericString),
			value:    []byte{49, 50},
			expected: string("12"),
		},
		{
			name:        "NumericString (invalid)",
			tag:         cryptobyte_asn1.Tag(asn1.TagNumericString),
			value:       []byte{80},
			expectedErr: "invalid NumericString",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := parseASN1String(tc.tag, tc.value)
			if err != nil && err.Error() != tc.expectedErr {
				t.Fatalf("parseASN1String returned unexpected error: got %q, want %q", err, tc.expectedErr)
			} else if err == nil && tc.expectedErr != "" {
				t.Fatalf("parseASN1String didn't fail, expected: %s", tc.expectedErr)
			}
			if out != tc.expected {
				t.Fatalf("parseASN1String returned unexpected value: got %q, want %q", out, tc.expected)
			}
		})
	}
}

// The SM2 public key with alg = oidPublicKeySM2 and SM2 curve
var sm2PublicKeyHex = "305a301406082a811ccf5501822d06082a811ccf5501822d0342000409586fff35c1f805b5c74f7281c3ade8fe211ffa70bf0ddd1c7268f62ae664331410e3039eeb03209afdc7fa834235c7b3ef528d32bf8b401eb98d32f498b4b7"

// The SM2 public key with alg = oidPublicKeySM2 and NIST P256 curve
var sm2NistP256PubulicKeyHex = "305a301406082a811ccf5501822d06082a8648ce3d0301070342000476110a45e7e86c1e96ba3c3300da61049a529c20a7ea7f026e50a2dbed60558087346bcb04cb0f0f8dcab8cca9967b8c7cc5aa0c874f024b73208b28f408bfca"

func TestParseSM2PublicKey(t *testing.T) {
	der, err := hex.DecodeString(sm2PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseSM2PublicKeyWithNistP256(t *testing.T) {
	der, err := hex.DecodeString(sm2NistP256PubulicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParsePKIXPublicKey(der)
	if err == nil || err.Error() != "x509: unsupported SM2 curve" {
		t.Fatal("should throw x509: unsupported SM2 curve")
	}
}

func TestParseCertificateNegativeMaxPathLength(t *testing.T) {
	certs := []string{
		// Certificate with MaxPathLen set to -1.
		`
-----BEGIN CERTIFICATE-----
MIIByTCCATKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRURVNU
MB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowDzENMAsGA1UEAxMEVEVT
VDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsaHglFuSicTT8TKfipgsSi3N
Wb/TcvuAhanFF1VGB+vS95kO7yFqyfRgX3GgOwT0KlJVsVjPjghEGR9RGTSLqkTD
UFbiBgm8+VEPMOrUtIHIHXhl+ye44AkOEStxfz7gjN/EAS2h8ffPKhvDTHOlShKw
Y3LQlxR0LdeJXq3eSqUCAwEAAaM1MDMwEgYDVR0TAQH/BAgwBgEB/wIB/zAdBgNV
HQ4EFgQUrbrk0tqQAEsce8uYifP0BIVhuFAwDQYJKoZIhvcNAQELBQADgYEAIkhV
ZBj1ThT+eyh50XsoU570NUysTg3Nj/3lbkEolzdcE+wu0CPXvgxLRM6Y62u1ey82
8d5VQHstzF4dXgc3W+O9UySa+CKdcHx/q7o7seOGXdysT0IJtAY3w66mFkuF7PIn
y9b7M5t6pmWjb7N0QqGuWeNqi4ZvS8gLKmVEgGY=
-----END CERTIFICATE-----
`,
		// Certificate with MaxPathLen set to -2.
		`
-----BEGIN CERTIFICATE-----
MIIByTCCATKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwRURVNU
MB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowDzENMAsGA1UEAxMEVEVT
VDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAsaHglFuSicTT8TKfipgsSi3N
Wb/TcvuAhanFF1VGB+vS95kO7yFqyfRgX3GgOwT0KlJVsVjPjghEGR9RGTSLqkTD
UFbiBgm8+VEPMOrUtIHIHXhl+ye44AkOEStxfz7gjN/EAS2h8ffPKhvDTHOlShKw
Y3LQlxR0LdeJXq3eSqUCAwEAAaM1MDMwEgYDVR0TAQH/BAgwBgEB/wIB/jAdBgNV
HQ4EFgQUrbrk0tqQAEsce8uYifP0BIVhuFAwDQYJKoZIhvcNAQELBQADgYEAGjIr
YGQc7Ods+BuKck7p+vpAMONM8SLEuUtKorCP3ecsO51MoA4/niLbgMHaOGNHwzMp
ajg0zLbY0Dj6Ml0VZ+lS3rjgTEhYXc626eZkoQqgUzL1jhe3S0ZbSxxmHMBKjJFl
d5l1tRhScKu2NBgm74nYmJxJYgvuTA38wGhRrGU=
-----END CERTIFICATE-----
`,
	}

	for _, cert := range certs {
		b, _ := pem.Decode([]byte(cert))
		_, err := ParseCertificate(b.Bytes)
		if err == nil || err.Error() != "x509: invalid basic constraints" {
			t.Errorf(`ParseCertificate() = %v; want = "x509: invalid basic constraints"`, err)
		}
	}
}
