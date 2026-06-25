package zuc

import (
	"github.com/emmansun/gmsm/internal/zuc"
)

const (
	// DefaultChunkSize is the default chunk size for chunked ZUC cipher (64KB).
	DefaultChunkSize = zuc.DefaultChunkSize
)

// ChunkedCipher implements stateless, chunk-based ZUC encryption.
// Each chunk is encrypted with an independent ZUC instance whose key
// is deterministically derived from the master key and chunk index
// via SM3(masterKey ‖ chunkIndex).
//
// This design is ideal for random-access scenarios such as HTTP Range
// requests on encrypted video files, where each range can be decrypted
// independently without maintaining cipher state.
type ChunkedCipher = zuc.ChunkedCipher

// NewChunkedCipher creates a chunk-based ZUC cipher for random-access encryption.
//
// If chunkSize <= 0, DefaultChunkSize (64KB) is used.
// The key must be 16 bytes (ZUC-128) or 32 bytes (ZUC-256).
// The iv must be 16 bytes (ZUC-128) or 23 bytes (ZUC-256).
func NewChunkedCipher(key, iv []byte, chunkSize int) (ChunkedCipher, error) {
	return zuc.NewChunkedCipher(key, iv, chunkSize)
}

// NewChunkedEEACipher creates a chunk-based ZUC-128 cipher using EEA IV construction.
// The key must be 16 bytes.
func NewChunkedEEACipher(key []byte, count, bearer, direction uint32, chunkSize int) (ChunkedCipher, error) {
	return zuc.NewChunkedEEACipher(key, count, bearer, direction, chunkSize)
}
