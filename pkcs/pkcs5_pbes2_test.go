package pkcs

import (
	"crypto/rand"
	"encoding/asn1"
	"testing"
)

func TestPBES2(t *testing.T) {
	testCases := []struct {
		name string
		opts PBESEncrypter
	}{
		{
			name: "PBKDF2-AES128-CBC",
			opts: NewPBESEncrypter(AES128CBC, NewPBKDF2Opts(SHA1, 16, 1000)),
		},
		{
			name: "PBKDF2-AES192-CBC",
			opts: NewPBESEncrypter(AES192CBC, NewPBKDF2Opts(SHA1, 16, 1000)),
		},
		{
			name: "PBKDF2-AES256-CBC",
			opts: NewPBESEncrypter(AES256CBC, NewPBKDF2Opts(SHA1, 16, 1000)),
		},
		{
			name: "PBKDF2(SHA256)-AES128-CBC",
			opts: NewPBESEncrypter(AES128CBC, NewPBKDF2Opts(SHA256, 16, 1000)),
		},
		{
			name: "PBKDF2(SHA256)-AES192-CBC",
			opts: NewPBESEncrypter(AES192CBC, NewPBKDF2Opts(SHA256, 16, 1000)),
		},
		{
			name: "PBKDF2(SHA256)-AES256-CBC",
			opts: NewPBESEncrypter(AES256CBC, NewPBKDF2Opts(SHA256, 16, 1000)),
		},
		{
			name: "PBKDF2(SM3)-SM4-CBC",
			opts: NewPBESEncrypter(SM4CBC, NewPBKDF2Opts(SM3, 16, 1000)),
		},
		{
			name: "SMPBES",
			opts: NewSMPBESEncrypter(16, 1000),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alg, ciphertext, err := tc.opts.Encrypt(rand.Reader, []byte("password"), []byte("pbes2"))
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			pbes2Opts := tc.opts.(*PBES2Opts)
			if !alg.Algorithm.Equal(pbes2Opts.pbesOID) {
				t.Errorf("unexpected algorithm: got %v, want %v", alg.Algorithm, tc.opts.(*PBES2Opts).pbesOID)
			}
			var param PBES2Params
			if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &param); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			plaintext, _, err := param.Decrypt([]byte("password"), ciphertext)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if string(plaintext) != "pbes2" {
				t.Errorf("unexpected plaintext: got %s, want pbes2", plaintext)
			}
		})
	}
}
