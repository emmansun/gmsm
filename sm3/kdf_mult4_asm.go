//go:build (amd64 || arm64) && !purego

package sm3

import "encoding/binary"

// prepare data template: remaining data + [ct] + padding + length
// p will be 1 or 2 blocks according to the length of remaining data
func prepareInitData(baseMD *digest, p []byte, len, lenStart uint64) {
	if baseMD.nx > 0 {
		copy(p, baseMD.x[:baseMD.nx])
	}
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	padlen := tmp[:lenStart+8]
	binary.BigEndian.PutUint64(padlen[lenStart:], len)
	copy(p[baseMD.nx+4:], padlen)
}

// p || state || words
// p = 64 * 4 * 2 = 512
// state = 8 * 16 = 128
// words = 68 * 16 = 1088
const preallocSizeBy4 = 1728

const parallelSize4 = 4

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
	tmpStart := parallelSize4 * blocks * BlockSize
	buffer := make([]byte, preallocSizeBy4)
	tmp := buffer[tmpStart:]
	// prepare processing data
	var dataPtrs [parallelSize4]*byte
	var data [parallelSize4][]byte
	var digs [parallelSize4]*[8]uint32
	var states [parallelSize4][8]uint32
	
	for j := 0; j < parallelSize4; j++ {
		digs[j] = &states[j]
		p := buffer[blocks*BlockSize*j:]
		data[j] = p
		dataPtrs[j] = &p[0]
		if j == 0 {
			prepareInitData(baseMD, p, len, t)
		} else {
			copy(p, data[0])
		}
	}

	var ct uint32 = 1
	k := make([]byte, keyLen)
	ret := k
	times := limit / parallelSize4
	for i := 0; i < times; i++ {
		for j := 0; j < parallelSize4; j++ {
			// prepare states
			states[j] = baseMD.h
			// prepare data
			binary.BigEndian.PutUint32(data[j][baseMD.nx:], ct)
			ct++
		}
		blockMultBy4(&digs[0], &dataPtrs[0], &tmp[0], blocks)
		copyResultsBy4(&states[0][0], &ret[0])
		ret = ret[Size*parallelSize4:]
	}
	remain := limit % parallelSize4
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

//go:noescape
func copyResultsBy4(dig *uint32, p *byte)
