// Adversarial vectors cover the exported ML-KEM parsing and decapsulation APIs.
package mlkem_test

import (
	"bytes"
	stdmlkem "crypto/mlkem"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/mlkem"
)

type vectorDecapsulationKey interface {
	Bytes() []byte
	Decapsulate([]byte) ([]byte, error)
}

func TestSemanticsVectors(t *testing.T) {
	suite, err := vectors.Load("mlkem_semantics.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("512", func(t *testing.T) {
		runMLKEMVectors(t, suite, "512", mlkem.NewDecapsulationKeyFromSeed512, mlkem.NewDecapsulationKey512, mlkem.NewEncapsulationKey512)
	})
	t.Run("768", func(t *testing.T) {
		runMLKEMVectors(t, suite, "768", mlkem.NewDecapsulationKeyFromSeed768, mlkem.NewDecapsulationKey768, mlkem.NewEncapsulationKey768)
	})
	t.Run("1024", func(t *testing.T) {
		runMLKEMVectors(t, suite, "1024", mlkem.NewDecapsulationKeyFromSeed1024, mlkem.NewDecapsulationKey1024, mlkem.NewEncapsulationKey1024)
	})
}

func vectorKeyBytes[Key interface{ Bytes() []byte }](key Key, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func runMLKEMVectors[Private vectorDecapsulationKey, Public interface{ Bytes() []byte }](t *testing.T, suite *vectors.Suite, parameter string, seedKey, privateKey func([]byte) (Private, error), publicKey func([]byte) (Public, error)) {
	t.Helper()
	for _, operation := range []string{"Seed", "PublicKey", "PrivateKey", "Decapsulate"} {
		t.Run(operation, func(t *testing.T) {
			group, err := suite.Group("MLKEM" + parameter + operation)
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range group.Tests {
				t.Run(fmt.Sprintf("tc%d", test.TCID), func(t *testing.T) {
					input := vectorHex(t, test.Input)
					original := bytes.Clone(input)
					var got []byte
					var err error
					switch operation {
					case "Seed":
						got, err = vectorKeyBytes(seedKey(input))
						if err == nil {
							digest := sha3.Sum256(got)
							got = digest[:]
						}
					case "PublicKey":
						got, err = vectorKeyBytes(publicKey(input))
					case "PrivateKey":
						got, err = vectorKeyBytes(privateKey(input))
					case "Decapsulate":
						key, keyErr := seedKey(input)
						if keyErr != nil {
							t.Fatal(keyErr)
						}
						ciphertext := vectorHex(t, test.Ciphertext)
						originalCiphertext := bytes.Clone(ciphertext)
						got, err = key.Decapsulate(ciphertext)
						if !bytes.Equal(ciphertext, originalCiphertext) {
							t.Fatal("Decapsulate mutated ciphertext")
						}
						if err == nil {
							repeated, repeatErr := key.Decapsulate(ciphertext)
							if repeatErr != nil || !bytes.Equal(got, repeated) {
								t.Fatal("Decapsulate is not deterministic")
							}
						}
						if parameter != "512" {
							standard, standardErr := standardDecapsulate(parameter, input, ciphertext)
							if (err == nil) != (standardErr == nil) || !bytes.Equal(got, standard) {
								t.Fatalf("standard library disagreement: got %x, %v; standard %x, %v", got, err, standard, standardErr)
							}
						}
					}
					if !bytes.Equal(input, original) {
						t.Fatal("operation mutated input")
					}
					if test.Result == "invalid" {
						if err == nil || got != nil {
							t.Fatalf("invalid input returned %x, %v: %s", got, err, test.Comment)
						}
						return
					}
					if err != nil {
						t.Fatalf("rejected valid input: %v: %s", err, test.Comment)
					}
					want := input
					if operation == "Seed" || operation == "Decapsulate" {
						want = vectorHex(t, test.Expected)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("got %x, want %x: %s", got, want, test.Comment)
					}
				})
			}
		})
	}
}

func standardDecapsulate(parameter string, seed, ciphertext []byte) ([]byte, error) {
	if parameter == "768" {
		key, err := stdmlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, err
		}
		return key.Decapsulate(ciphertext)
	}
	key, err := stdmlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, err
	}
	return key.Decapsulate(ciphertext)
}

func vectorHex(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
