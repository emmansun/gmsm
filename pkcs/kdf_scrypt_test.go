package pkcs

import (
	"bytes"
	"testing"
)

func TestScryptDeriveKey(t *testing.T) {
	opts := NewScryptOpts(8, 16384, 8, 1)
	key, params, err := opts.DeriveKey([]byte("password"), []byte("saltsalt"), 32)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("unexpected key length: got %d, want 32", len(key))
	}
	if params.KeyLength() != 32 {
		t.Errorf("unexpected key length: got %d, want 32", params.KeyLength())
	}
	if len(params.(scryptParams).Salt) != opts.SaltSize {
		t.Errorf("unexpected salt length: got %d, want %d", len(params.(scryptParams).Salt), opts.SaltSize)
	}
	if params.(scryptParams).CostParameter != opts.CostParameter {
		t.Errorf("unexpected cost parameter: got %d, want %d", params.(scryptParams).CostParameter, opts.CostParameter)
	}
	if params.(scryptParams).BlockSize != opts.BlockSize {
		t.Errorf("unexpected block size: got %d, want %d", params.(scryptParams).BlockSize, opts.BlockSize)
	}
	if params.(scryptParams).ParallelizationParameter != opts.ParallelizationParameter {
		t.Errorf("unexpected parallelization parameter: got %d, want %d", params.(scryptParams).ParallelizationParameter, opts.ParallelizationParameter)
	}
	key2, err := params.DeriveKey(nil, []byte("password"), 32)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !bytes.Equal(key, key2) {
		t.Errorf("unexpected key: got %x, want %x", key2, key)
	}
}
