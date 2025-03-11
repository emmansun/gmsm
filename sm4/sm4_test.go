package sm4

import (
	"reflect"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest"
)

type CryptTest struct {
	key []byte
	in  []byte
	out []byte
}

var encryptTests = []CryptTest{
	{
		// Appendix 1.
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		[]byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46},
	},
}

func Test_sample1(t *testing.T) {
	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	expected := []byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46}
	c, err := NewCipher(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 16)
	c.Encrypt(dst, src)
	if !reflect.DeepEqual(dst, expected) {
		t.Errorf("expected=%x, result=%x\n", expected, dst)
	}
	c.Decrypt(dst, expected)
	if !reflect.DeepEqual(dst, src) {
		t.Errorf("expected=%x, result=%x\n", src, dst)
	}
}

func Test_sample2(t *testing.T) {
	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	expected := []byte{0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66}
	c, err := NewCipher(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 16)
	copy(dst, src)
	n := 1000000
	if testing.Short() {
		n = 1000
		expected = []byte{215, 53, 233, 28, 197, 104, 156, 243, 18, 188, 193, 239, 183, 64, 232, 19}
	}
	for i := 0; i < n; i++ {
		c.Encrypt(dst, dst)
	}
	if !reflect.DeepEqual(dst, expected) {
		t.Errorf("expected=%x, result=%x\n", expected, dst)
	}
}

func TestEncryptDecryptPanic(t *testing.T) {
	key := make([]byte, 16)
	src := make([]byte, 15)
	dst := make([]byte, 16)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	shouldPanic(t, func() { c.Encrypt(dst, src) })
	shouldPanic(t, func() { c.Encrypt(src, dst) })
	shouldPanic(t, func() { c.Decrypt(dst, src) })
	shouldPanic(t, func() { c.Decrypt(src, dst) })

	src = make([]byte, 32)
	shouldPanic(t, func() { c.Encrypt(src, src[1:]) })
	shouldPanic(t, func() { c.Encrypt(src[1:], src) })
	shouldPanic(t, func() { c.Decrypt(src, src[1:]) })
	shouldPanic(t, func() { c.Decrypt(src[1:], src) })
}

func shouldPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() { _ = recover() }()
	f()
	t.Errorf("should have panicked")
}

// Test SM4 against the general cipher.Block interface tester
func TestSM4Block(t *testing.T) {
	t.Run("SM4", func(t *testing.T) {
		cryptotest.TestBlock(t, 16, NewCipher)
	})
}

func BenchmarkEncrypt(b *testing.B) {
	tt := encryptTests[0]
	c, err := NewCipher(tt.key)
	if err != nil {
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(tt.in))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(out, tt.in)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	tt := encryptTests[0]
	c, err := NewCipher(tt.key)
	if err != nil {
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(tt.out))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(out, tt.out)
	}
}
