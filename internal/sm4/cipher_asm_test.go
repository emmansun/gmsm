//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package sm4

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

func TestWithoutGFMUL(t *testing.T) {
	key := make([]byte, 16)
	src := make([]byte, 16)
	var dst []byte
	var nonce [12]byte
	var c cipher.Block
	var err error

	if supportSM4 {
		c, err = newCipherNI(key)
	} else if !supportsAES {
		c, err = newCipherGeneric(key)
	} else {
		blocks := 4
		if useAVX2 {
			blocks = 8
		}
		c1 := &sm4CipherAsm{sm4Cipher{}, blocks, blocks * BlockSize}
		expandKeyAsm(&key[0], &ck[0], &c1.enc[0], &c1.dec[0], INST_AES)
		c = c1
	}
	if err != nil {
		t.Fatal(err)
	}

	var sm4gcm cipher.AEAD
	sm4gcm, err = cipher.NewGCM(c)
	if err != nil {
		t.Fatal(err)
	}
	dst = sm4gcm.Seal(nil, nonce[:], src, nil)
	src, err = sm4gcm.Open(nil, nonce[:], dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, src) {
		t.Errorf("bad encryption")
	}
}

func TestEncryptBlockAsm(t *testing.T) {
	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	expected := []byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46}
	encRes2 := make([]uint32, 32)
	decRes2 := make([]uint32, 32)
	expandKeyAsm(&src[0], &ck[0], &encRes2[0], &decRes2[0], 0)
	dst := make([]byte, 16)
	encryptBlockAsm(&encRes2[0], &dst[0], &src[0], 0)
	if !bytes.Equal(dst, expected) {
		t.Errorf("expected=%x, result=%x\n", expected, dst)
	}
	encryptBlockAsm(&decRes2[0], &dst[0], &expected[0], 0)
	if !bytes.Equal(dst, src) {
		t.Errorf("expected=%x, result=%x\n", src, dst)
	}
}

func TestEncryptBlocksWithAESNI(t *testing.T) {
	if !supportsAES {
		t.Skip("AES-NI not available")
	}

	blocks := 4
	if useAVX2 {
		blocks = 8
	}

	src := make([]byte, 16*blocks)
	expected := make([]byte, 16*blocks)
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	for i := 0; i < blocks; i++ {
		copy(src[i*16:], key)
		copy(expected[i*16:], []byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46})
	}

	c := &sm4CipherAsm{sm4Cipher{}, blocks, blocks * BlockSize}
	expandKeyAsm(&key[0], &ck[0], &c.enc[0], &c.dec[0], INST_AES)
	dst := make([]byte, 16*blocks)

	c.EncryptBlocks(dst, src)
	if !bytes.Equal(dst, expected) {
		t.Errorf("expected=%x, result=%x\n", expected, dst)
	}

	c.DecryptBlocks(dst, expected)
	if !bytes.Equal(dst, src) {
		t.Errorf("expected=%x, result=%x\n", src, dst)
	}
}

func TestEncryptBlocksDoubleWithAESNI(t *testing.T) {
	if !supportsAES {
		t.Skip("AES-NI not available")
	}

	blocks := 4
	if useAVX2 {
		blocks = 8
	}

	src := make([]byte, 2*16*blocks)
	expected := make([]byte, 2*16*blocks)
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	for i := 0; i < 2*blocks; i++ {
		copy(src[i*16:], key)
		copy(expected[i*16:], []byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46})
	}

	c := &sm4CipherAsm{sm4Cipher{}, blocks, blocks * BlockSize}
	expandKeyAsm(&key[0], &ck[0], &c.enc[0], &c.dec[0], INST_AES)
	dst := make([]byte, 2*16*blocks)

	c.EncryptBlocks(dst, src)
	if !bytes.Equal(dst, expected) {
		t.Errorf("expected=%x, result=%x\n", expected, dst)
	}

	c.DecryptBlocks(dst, expected)
	if !bytes.Equal(dst, src) {
		t.Errorf("expected=%x, result=%x\n", src, dst)
	}
}

func BenchmarkExpandAESNI(b *testing.B) {
	c := &sm4Cipher{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expandKeyAsm(&encryptTests[0].key[0], &ck[0], &c.enc[0], &c.dec[0], INST_AES)
	}
}

func BenchmarkEncryptAsm(b *testing.B) {
	src := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	encRes2 := make([]uint32, 32)
	decRes2 := make([]uint32, 32)
	expandKeyAsm(&src[0], &ck[0], &encRes2[0], &decRes2[0], 0)
	dst := make([]byte, 16)
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptBlockAsm(&encRes2[0], &dst[0], &src[0], 0)
	}
}
