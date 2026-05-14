package rand

import (
	"bytes"
	"encoding/hex"

	"github.com/emmansun/gmsm/drbg"
)

// selfTest runs a known-answer test (KAT) for the SM3 Hash DRBG per
// GM/T 0105-2021 Section 5.6.6. It verifies Instantiate, Reseed, and
// Generate using a published test vector.
//
// Panics if any output does not match the expected value.
func selfTest() {
	// Test vector: SM3 Hash DRBG, GM mode (from drbg package test suite).
	entropyInput := mustHex("63363377e41e86468deb0ab4a8ed683f6a134e47e014c700454e81e95358a569")
	nonce := mustHex("808aa38f2a72a62359915a9f8a04ca68")

	// 1. Instantiate
	hd, err := drbg.NewGMHashDrbg(drbg.SECURITY_LEVEL_ONE, entropyInput, nonce, nil)
	if err != nil {
		panic("rand: DRBG self-test: instantiate failed: " + err.Error())
	}

	// 2. Reseed
	entropyReseed := mustHex("e62b8a8ee8f141b6980566e3bfe3c04903dad4ac2cdf9f2280010a6739bc83d3")
	if err := hd.Reseed(entropyReseed, nil); err != nil {
		panic("rand: DRBG self-test: reseed failed: " + err.Error())
	}

	// 3. Generate (first call, output discarded per test vector flow)
	output := make([]byte, 32) // SM3 output = 256 bits
	if err := hd.Generate(output, nil); err != nil {
		panic("rand: DRBG self-test: first generate failed: " + err.Error())
	}

	// 4. Generate (second call, output must match known answer)
	if err := hd.Generate(output, nil); err != nil {
		panic("rand: DRBG self-test: second generate failed: " + err.Error())
	}

	expected := mustHex("00d98d35a2fab8df23e9e1fb9aad143d62c0759eb79e15c37e8f2bc5064e68da")
	if !bytes.Equal(output, expected) {
		panic("rand: DRBG self-test failed: output mismatch")
	}

	hd.Destroy()
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("rand: invalid hex in self-test: " + err.Error())
	}
	return b
}
