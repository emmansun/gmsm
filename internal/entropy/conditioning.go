package entropy

import (
	"github.com/emmansun/gmsm/internal/byteorder"
	"github.com/emmansun/gmsm/internal/sm3"
)

// SeedSize is the seed size for SM3 Hash DRBG (55 bytes).
const SeedSize = 55

// hashDf implements Hash_df per SP 800-90A Section 10.3.1 using SM3.
//
// Hash_df(input_string, no_of_bits_to_return):
//
//	temp = ""
//	len = ceil(no_of_bits_to_return / outlen)
//	counter = 1
//	for i = 1 to len:
//	    temp = temp || Hash(counter || no_of_bits_to_return || input_string)
//	    counter = counter + 1
//	return leftmost(temp, no_of_bits_to_return)
func hashDf(inputString []byte, returnBytes int) []byte {
	hashSize := sm3.Size
	limit := (returnBytes + hashSize - 1) / hashSize
	var requireBits [4]byte
	byteorder.BEPutUint32(requireBits[:], uint32(returnBytes<<3))

	result := make([]byte, returnBytes)
	var counter byte = 1
	for i := range limit {
		h := sm3.New()
		h.Write([]byte{counter})
		h.Write(requireBits[:])
		h.Write(inputString)
		digest := h.Sum(nil)
		copy(result[i*hashSize:], digest)
		counter++
	}
	return result
}
