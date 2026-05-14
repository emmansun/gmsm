package rand_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/emmansun/gmsm/rand"
	"github.com/emmansun/gmsm/sm2"
)

func ExampleRead() {
	buf := make([]byte, 16)
	n, err := rand.Read(buf)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(n == 16)
	fmt.Println(!bytes.Equal(buf, make([]byte, 16)))
	// Output:
	// true
	// true
}

func ExampleReader() {
	buf := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(n == 16)
	fmt.Println(!bytes.Equal(buf, make([]byte, 16)))
	// Output:
	// true
	// true
}

func TestSM2GenerateKey(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test message")
	sig, err := key.SignWithSM2(rand.Reader, nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !sm2.VerifyASN1WithSM2(&key.PublicKey, nil, msg, sig) {
		t.Error("signature verification failed")
	}
}
