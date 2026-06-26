package zuc

import (
	"encoding/binary"

	"github.com/emmansun/gmsm/internal/alias"
	sm3internal "github.com/emmansun/gmsm/internal/sm3"
)

const (
	// DefaultChunkSize is the default chunk size for chunked ZUC cipher (64KB).
	DefaultChunkSize = 64 * 1024
)

// ChunkedCipher provides stateless, chunk-based ZUC encryption.
type ChunkedCipher interface {
	// XORChunk XORs the data of a single chunk with the ZUC keystream.
	XORChunk(dst, src []byte, chunkIndex uint64) error
	// XORKeyStreamAt XORs src with the keystream starting at byte offset.
	XORKeyStreamAt(dst, src []byte, offset uint64)
	// ChunkSize returns the chunk size in bytes.
	ChunkSize() int
}

// chunkedCipher implements stateless, chunk-based ZUC encryption.
// Each chunk is encrypted with an independent ZUC instance whose key
// is deterministically derived from the master key and chunk index.
type chunkedCipher struct {
	masterKey []byte
	iv        []byte
	chunkSize int
	keySize   int // 16 for ZUC-128, 32 for ZUC-256
}

// NewChunkedCipher creates a chunk-based ZUC cipher for random-access encryption.
// Each chunk of chunkSize bytes is encrypted with an independent ZUC instance
// whose key is deterministically derived via SM3(masterKey ‖ chunkIndex).
//
// If chunkSize <= 0, DefaultChunkSize (64KB) is used.
// The key must be 16 bytes (ZUC-128) or 32 bytes (ZUC-256).
// The iv must be 16 bytes (ZUC-128) or 23 bytes (ZUC-256).
func NewChunkedCipher(key, iv []byte, chunkSize int) (*chunkedCipher, error) {
	keySize := len(key)
	if keySize != 16 && keySize != 32 {
		return nil, KeySizeError(keySize)
	}
	ivLen := len(iv)
	if keySize == 16 && ivLen != IVSize128 {
		return nil, IVSizeError(ivLen)
	}
	if keySize == 32 && ivLen != IVSize256 {
		return nil, IVSizeError(ivLen)
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	mk := make([]byte, keySize)
	copy(mk, key)
	civ := make([]byte, ivLen)
	copy(civ, iv)
	return &chunkedCipher{
		masterKey: mk,
		iv:        civ,
		chunkSize: chunkSize,
		keySize:   keySize,
	}, nil
}

// NewChunkedEEACipher creates a chunk-based ZUC-128 cipher using EEA IV construction.
// The key must be 16 bytes. See NewChunkedCipher for chunk semantics.
func NewChunkedEEACipher(key []byte, count, bearer, direction uint32, chunkSize int) (*chunkedCipher, error) {
	return NewChunkedCipher(key, construcIV4EEA(count, bearer, direction), chunkSize)
}

// deriveSubKey derives the ZUC key for a specific chunk index using
// SM3(masterKey ‖ big-endian chunk index), truncated to keySize bytes.
func (c *chunkedCipher) deriveSubKey(chunkIndex uint64) []byte {
	h := sm3internal.New()
	h.Write(c.masterKey)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], chunkIndex)
	h.Write(buf[:])
	sum := h.Sum(nil)
	return sum[:c.keySize]
}

// ChunkSize returns the chunk size in bytes.
func (c *chunkedCipher) ChunkSize() int {
	return c.chunkSize
}

// XORChunk XORs the data of a single chunk (identified by chunkIndex) with the ZUC keystream.
// len(data) must not exceed chunkSize.
func (c *chunkedCipher) XORChunk(dst, src []byte, chunkIndex uint64) error {
	if len(dst) < len(src) {
		panic("zuc: output smaller than input")
	}
	if len(src) == 0 {
		return nil
	}
	if len(src) > c.chunkSize {
		panic("zuc: chunk data exceeds chunk size")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("zuc: invalid buffer overlap")
	}

	subKey := c.deriveSubKey(chunkIndex)
	cipher, err := NewCipher(subKey, c.iv)
	if err != nil {
		return err
	}
	cipher.XORKeyStream(dst, src)
	return nil
}

// XORKeyStreamAt XORs src with the ZUC keystream starting at the given byte offset.
// This is a stateless operation: each affected chunk is independently derived
// from the master key, so no cipher state is carried between calls.
func (c *chunkedCipher) XORKeyStreamAt(dst, src []byte, offset uint64) {
	if len(dst) < len(src) {
		panic("zuc: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("zuc: invalid buffer overlap")
	}
	if len(src) == 0 {
		return
	}

	cs := uint64(c.chunkSize)
	pos := uint64(0)

	for pos < uint64(len(src)) {
		absOffset := offset + pos
		chunkIndex := absOffset / cs
		chunkOffset := absOffset % cs

		// how many bytes to process in this chunk
		remaining := uint64(len(src)) - pos
		avail := cs - chunkOffset
		n := remaining
		if avail < n {
			n = avail
		}

		// derive sub-key and create per-chunk cipher
		subKey := c.deriveSubKey(chunkIndex)
		cipher, err := NewCipher(subKey, c.iv)
		if err != nil {
			panic("zuc: chunked cipher key derivation failed: " + err.Error())
		}

		// advance to chunk-internal offset
		if chunkOffset > 0 {
			cipher.seek(chunkOffset)
		}

		cipher.XORKeyStream(dst[pos:pos+n], src[pos:pos+n])
		pos += n
	}
}
