//go:build amd64
// +build amd64

package sm4

import (
	"encoding/hex"
	"testing"
)

func createGcm() *gcmAsm {
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	c := sm4CipherAsm{sm4Cipher{make([]uint32, rounds), make([]uint32, rounds)}, 4, 64}
	expandKeyAsm(&key[0], &ck[0], &c.enc[0], &c.dec[0])
	c1 := &sm4CipherGCM{c}
	g := &gcmAsm{}
	g.cipher = &c1.sm4CipherAsm
	g.tagSize = 16
	gcmSm4Init(&g.bytesProductTable, g.cipher.enc)
	return g
}

var sm4GCMTests = []struct {
	plaintext string
}{
	{ // case 0: < 16
		"abcdefg",
	},
	{ // case 1: = 16
		"abcdefgabcdefghg",
	},
	{ // case 2: > 16 , < 64
		"abcdefgabcdefghgabcdefgabcdefghgaaa",
	},
	{ // case 3: = 64
		"abcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghg",
	},
	{ // case 4: > 64, < 128
		"abcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgaaa",
	},
	{ // case 5: = 128
		"abcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghg",
	},
	{ // case 6: 227 > 128, < 256, 128 + 64 + 35
		"abcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgaaa",
	},
	{ // case 7: = 256
		"abcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghg",
	},
	{ // case 8: > 256, = 355
		"abcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgabcdefgabcdefghgaaa",
	},
}

func initCounter(i byte, counter *[16]byte) {
	copy(counter[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	counter[gcmBlockSize-1] = i
}

func resetTag(tag *[16]byte) {
	for j := 0; j < 16; j++ {
		tag[j] = 0
	}
}

func TestGcmSm4Enc(t *testing.T) {
	var counter1, counter2 [16]byte
	gcm := createGcm()
	var tagOut1, tagOut2 [gcmTagSize]byte

	for i, test := range sm4GCMTests {
		initCounter(2, &counter1)
		initCounter(1, &counter2)

		gcmSm4Data(&gcm.bytesProductTable, []byte("emmansun"), &tagOut1)
		out1 := make([]byte, len(test.plaintext)+gcm.tagSize)
		gcm.counterCrypt(out1, []byte(test.plaintext), &counter1)
		gcmSm4Data(&gcm.bytesProductTable, out1[:len(test.plaintext)], &tagOut1)

		out2 := make([]byte, len(test.plaintext)+gcm.tagSize)
		gcmSm4Data(&gcm.bytesProductTable, []byte("emmansun"), &tagOut2)
		gcmSm4Enc(&gcm.bytesProductTable, out2, []byte(test.plaintext), &counter2, &tagOut2, gcm.cipher.enc)
		if hex.EncodeToString(out1) != hex.EncodeToString(out2) {
			t.Errorf("#%d: out expected %s, got %s", i, hex.EncodeToString(out1), hex.EncodeToString(out2))
		}
		if hex.EncodeToString(tagOut1[:]) != hex.EncodeToString(tagOut2[:]) {
			t.Errorf("#%d: tag expected %s, got %s", i, hex.EncodeToString(tagOut1[:]), hex.EncodeToString(tagOut2[:]))
		}
		resetTag(&tagOut1)
		resetTag(&tagOut2)
	}
}

func TestGcmSm4Dec(t *testing.T) {
	var counter1, counter2 [16]byte
	gcm := createGcm()
	var tagOut1, tagOut2 [gcmTagSize]byte

	for i, test := range sm4GCMTests {
		initCounter(2, &counter1)
		initCounter(1, &counter2)

		gcmSm4Data(&gcm.bytesProductTable, []byte("emmansun"), &tagOut1)
		out1 := make([]byte, len(test.plaintext)+gcm.tagSize)
		gcm.counterCrypt(out1, []byte(test.plaintext), &counter1)
		gcmSm4Data(&gcm.bytesProductTable, out1[:len(test.plaintext)], &tagOut1)

		out1 = out1[:len(test.plaintext)]

		out2 := make([]byte, len(test.plaintext)+gcm.tagSize)
		gcmSm4Data(&gcm.bytesProductTable, []byte("emmansun"), &tagOut2)
		gcmSm4Dec(&gcm.bytesProductTable, out2, out1, &counter2, &tagOut2, gcm.cipher.enc)

		if hex.EncodeToString([]byte(test.plaintext)) != hex.EncodeToString(out2[:len(test.plaintext)]) {
			t.Errorf("#%d: out expected %s, got %s", i, hex.EncodeToString([]byte(test.plaintext)), hex.EncodeToString(out2[:len(test.plaintext)]))
		}
		if hex.EncodeToString(tagOut1[:]) != hex.EncodeToString(tagOut2[:]) {
			t.Errorf("#%d: tag expected %s, got %s", i, hex.EncodeToString(tagOut1[:]), hex.EncodeToString(tagOut2[:]))
		}
		resetTag(&tagOut1)
		resetTag(&tagOut2)
	}
}
