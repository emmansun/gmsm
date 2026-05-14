package entropy

import "crypto/rand"

// readOSEntropy fills dst with entropy from the operating system's
// cryptographic random number generator (via crypto/rand.Reader).
func readOSEntropy(dst []byte) {
	// crypto/rand.Read never returns an error on supported platforms.
	_, err := rand.Read(dst)
	if err != nil {
		panic("entropy: failed to read OS entropy: " + err.Error())
	}
}
