package drbg_test

import (
	"bytes"
	"fmt"

	"github.com/emmansun/gmsm/drbg"
)

func ExampleNewGmCtrDrbgPrng() {
	prng, err := drbg.NewGmCtrDrbgPrng(nil, 32, drbg.SECURITY_LEVEL_TEST, nil)
	if err != nil {
		panic(err)
	}
	c := 10
	b := make([]byte, c)
	_, err = prng.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// The slice should now contain random bytes instead of only zeroes.
	fmt.Println(bytes.Equal(b, make([]byte, c)))

	// Output:
	// false
}

func ExampleNewGmHashDrbgPrng() {
	prng, err := drbg.NewGmHashDrbgPrng(nil, 32, drbg.SECURITY_LEVEL_TEST, nil)
	if err != nil {
		panic(err)
	}
	c := 10
	b := make([]byte, c)
	_, err = prng.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// The slice should now contain random bytes instead of only zeroes.
	fmt.Println(bytes.Equal(b, make([]byte, c)))

	// Output:
	// false
}
