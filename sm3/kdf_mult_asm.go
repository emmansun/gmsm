//go:build (amd64 || arm64) && !purego

package sm3

import "encoding/binary"

func prepareData(baseMD *digest, p []byte, ct uint32, len, t uint64) {
	if baseMD.nx > 0 {
		copy(p, baseMD.x[:baseMD.nx])
	}
	binary.BigEndian.PutUint32(p[baseMD.nx:], ct)
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	padlen := tmp[:t+8]
	binary.BigEndian.PutUint64(padlen[t:], len)
	copy(p[baseMD.nx+4:], padlen)
}

func copyResult(result []byte, dig *[8]uint32) {
	binary.BigEndian.PutUint32(result[0:], dig[0])
	binary.BigEndian.PutUint32(result[4:], dig[1])
	binary.BigEndian.PutUint32(result[8:], dig[2])
	binary.BigEndian.PutUint32(result[12:], dig[3])
	binary.BigEndian.PutUint32(result[16:], dig[4])
	binary.BigEndian.PutUint32(result[20:], dig[5])
	binary.BigEndian.PutUint32(result[24:], dig[6])
	binary.BigEndian.PutUint32(result[28:], dig[7])
}

// p || state || words
// p = 64 * 4 * 2 = 512
// state = 8 * 16 = 128
// words = 68 * 16 = 1088
const preallocSize = 1728

func kdfBy4(baseMD *digest, keyLen int, limit int) []byte {
	if limit < 4 {
		return kdfGeneric(baseMD, keyLen, limit)
	}
	
	var t uint64
	blocks := 1
	len := baseMD.len + 4
	remainlen := len % 64
	if remainlen < 56 {
		t = 56 - remainlen
	} else {
		t = 64 + 56 - remainlen
		blocks = 2
	}
	len <<= 3
	// prepare temporary buffer
	tmpStart := 4 * blocks * BlockSize
	buffer := make([]byte, preallocSize)
	tmp := buffer[tmpStart:]
	// prepare processing data
	var data [4]*byte
	var digs [4]*[8]uint32
	var states [4][8]uint32
	for j := 0; j < 4; j++ {
		digs[j] = &states[j]
	}

	var ct uint32 = 1
	k := make([]byte, keyLen)
	ret := k
	times := limit / 4
	for i := 0; i < times; i++ {
		for j := 0; j < 4; j++ {
			// prepare states
			states[j] = baseMD.h
			// prepare data
			p := buffer[blocks*BlockSize*j:]
			data[j] = &p[0]
			prepareData(baseMD, p, ct, len, t)
			ct++
		}
		blockMultBy4(&digs[0], &data[0], &tmp[0], blocks)
		for j := 0; j < 4; j++ {
			copyResult(ret, digs[j])
			ret = ret[Size:]
		}
	}
	remain := limit % 4
	for i := 0; i < remain; i++ {
		binary.BigEndian.PutUint32(tmp[:], ct)
		md := *baseMD
		md.Write(tmp[:4])
		h := md.checkSum()
		copy(ret[i*Size:], h[:])
		ct++
	}

	return k
}

//go:noescape
func blockMultBy4(dig **[8]uint32, p **byte, buffer *byte, blocks int)
