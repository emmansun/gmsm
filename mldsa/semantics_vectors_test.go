// Adversarial vectors exercise exported ML-DSA APIs without bypassing decoding.
package mldsa_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/mldsa"
)

type vectorPrivateKey interface {
	Bytes() []byte
	Public() crypto.PublicKey
	SignMessage(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

type vectorPublicKey interface {
	Bytes() []byte
	VerifyWithOptions([]byte, []byte, crypto.SignerOpts) bool
}

func TestSemanticsVectors(t *testing.T) {
	suite, err := vectors.Load("mldsa_semantics.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("44", func(t *testing.T) {
		runMLDSAVectors(t, suite, "44", mldsa.NewKey44, mldsa.NewPrivateKey44, mldsa.NewPublicKey44)
	})
	t.Run("65", func(t *testing.T) {
		runMLDSAVectors(t, suite, "65", mldsa.NewKey65, mldsa.NewPrivateKey65, mldsa.NewPublicKey65)
	})
	t.Run("87", func(t *testing.T) {
		runMLDSAVectors(t, suite, "87", mldsa.NewKey87, mldsa.NewPrivateKey87, mldsa.NewPublicKey87)
	})
}

func runMLDSAVectors[Seed vectorPrivateKey, Private vectorPrivateKey, Public vectorPublicKey](t *testing.T, suite *vectors.Suite, parameter string, seedKey func([]byte) (Seed, error), privateKey func([]byte) (Private, error), publicKey func([]byte) (Public, error)) {
	t.Helper()
	for _, operation := range []string{"Seed", "PublicKey", "PrivateKey", "Verify", "Sign"} {
		t.Run(operation, func(t *testing.T) {
			group, err := suite.Group("MLDSA" + parameter + operation)
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range group.Tests {
				t.Run(fmt.Sprintf("tc%d", test.TCID), func(t *testing.T) {
					input := vectorHex(t, test.Input)
					original := bytes.Clone(input)
					message := vectorHex(t, test.Msg)
					context := vectorHex(t, test.Context)
					opts := &mldsa.Options{Context: context}
					var got []byte
					var err error
					switch operation {
					case "Seed":
						key, keyErr := seedKey(input)
						err = keyErr
						if err == nil {
							got = key.Public().(interface{ Bytes() []byte }).Bytes()
						}
					case "PublicKey":
						got, err = vectorKeyBytes(publicKey(input))
					case "PrivateKey":
						got, err = vectorKeyBytes(privateKey(input))
					case "Verify":
						key, keyErr := publicKey(vectorHex(t, test.Pub))
						if keyErr != nil {
							t.Fatal(keyErr)
						}
						signature := vectorHex(t, test.Sig)
						originalSignature := bytes.Clone(signature)
						originalMessage, originalContext := bytes.Clone(message), bytes.Clone(context)
						valid := key.VerifyWithOptions(signature, message, opts)
						if valid != (test.Result == "valid") {
							t.Fatalf("VerifyWithOptions = %v, want %s: %s", valid, test.Result, test.Comment)
						}
						if !bytes.Equal(signature, originalSignature) || !bytes.Equal(message, originalMessage) || !bytes.Equal(context, originalContext) {
							t.Fatal("VerifyWithOptions mutated input")
						}
						return
					case "Sign":
						key, keyErr := seedKey(input)
						if keyErr != nil {
							t.Fatal(keyErr)
						}
						randomnessLength := 32
						if slices.Contains(test.Flags, "ShortRandomness") {
							randomnessLength = 31
						}
						got, err = key.SignMessage(bytes.NewReader(make([]byte, randomnessLength)), message, opts)
						if err == nil {
							pub, parseErr := publicKey(vectorHex(t, test.Pub))
							if parseErr != nil {
								t.Fatal(parseErr)
							}
							if !pub.VerifyWithOptions(got, message, opts) {
								t.Fatal("generated signature did not verify")
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
					if operation == "Seed" || operation == "Sign" {
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

func vectorKeyBytes[Key interface{ Bytes() []byte }](key Key, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return key.Bytes(), nil
}

func vectorHex(t *testing.T, input string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
