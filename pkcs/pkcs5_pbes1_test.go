package pkcs

import (
	"crypto/rand"
	"testing"
)

func TestPBES1(t *testing.T) {
	var testCases []*PBES1

	pbes1, err := NewPbeWithMD2AndDESCBC(rand.Reader, 8, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testCases = append(testCases, pbes1)

	pbes1, err = NewPbeWithMD2AndRC2CBC(rand.Reader, 8, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testCases = append(testCases, pbes1)

	pbes1, err = NewPbeWithMD5AndDESCBC(rand.Reader, 8, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testCases = append(testCases, pbes1)

	pbes1, err = NewPbeWithMD5AndRC2CBC(rand.Reader, 8, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testCases = append(testCases, pbes1)

	pbes1, err = NewPbeWithSHA1AndDESCBC(rand.Reader, 8, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testCases = append(testCases, pbes1)

	pbes1, err = NewPbeWithSHA1AndRC2CBC(rand.Reader, 8, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testCases = append(testCases, pbes1)

	for _, pbes1 := range testCases {
		t.Run("", func(t *testing.T) {
			_, ciphertext, err := pbes1.Encrypt(rand.Reader, []byte("password"), []byte("pbes1"))
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			plaintext, _, err := pbes1.Decrypt([]byte("password"), ciphertext)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if string(plaintext) != "pbes1" {
				t.Errorf("unexpected plaintext: got %s, want password", plaintext)
			}
		})
	}
}
