package pkcs

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509/pkix"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestNewHashFromPRF(t *testing.T) {
	h, err := newHashFromPRF(oidPKCS5PBKDF2, pkix.AlgorithmIdentifier{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	hash := h()
	if hash.Size() != sha1.Size {
		t.Errorf("unexpected hash size: got %d, want %d", hash.Size(), sha1.Size)
	}
	h, err = newHashFromPRF(oidSMPBKDF, pkix.AlgorithmIdentifier{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	hash = h()
	if hash.Size() != sm3.Size {
		t.Errorf("unexpected hash size: got %d, want %d", hash.Size(), sm3.Size)
	}
}

func TestPBKDF2DeriveKey(t *testing.T) {
	testCases := []struct {
		name string
		opts PBKDF2Opts
	}{
		{
			name: "PBKDF2-SHA1",
			opts: NewPBKDF2Opts(SHA1, 16, 1000),
		},
		{
			name: "PBKDF2-SHA256",
			opts: NewPBKDF2Opts(SHA256, 16, 1000),
		},
		{
			name: "SMPBKDF2",
			opts: NewSMPBKDF2Opts(16, 1000),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, params, err := tc.opts.DeriveKey([]byte("password"), []byte("saltsaltsaltsalt"), 32)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if len(key) != 32 {
				t.Errorf("unexpected key length: got %d, want 32", len(key))
			}
			if params.KeyLength() != 32 {
				t.Errorf("unexpected key length: got %d, want 32", params.KeyLength())
			}
			if len(params.(pbkdf2Params).Salt) != tc.opts.SaltSize {
				t.Errorf("unexpected salt length: got %d, want %d", len(params.(pbkdf2Params).Salt), tc.opts.SaltSize)
			}
			if params.(pbkdf2Params).IterationCount != tc.opts.IterationCount {
				t.Errorf("unexpected iteration count: got %d, want %d", params.(pbkdf2Params).IterationCount, tc.opts.IterationCount)
			}
			if params.(pbkdf2Params).KeyLen != 32 {
				t.Errorf("unexpected key length: got %d, want 32", params.(pbkdf2Params).KeyLen)
			}
			key2, err := params.DeriveKey(nil, []byte("password"), 32)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !bytes.Equal(key, key2) {
				t.Errorf("unexpected key: got %x, want %x", key2, key)
			}
		})
	}
}
