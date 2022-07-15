//go:build !race
// +build !race

package pkcs8_test

import (
	"encoding/pem"
	"testing"

	"github.com/emmansun/gmsm/pkcs8"
)

// From https://tools.ietf.org/html/rfc7914
const encryptedRFCscrypt = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHiME0GCSqGSIb3DQEFDTBAMB8GCSsGAQQB2kcECzASBAVNb3VzZQIDEAAAAgEI
AgEBMB0GCWCGSAFlAwQBKgQQyYmguHMsOwzGMPoyObk/JgSBkJb47EWd5iAqJlyy
+ni5ftd6gZgOPaLQClL7mEZc2KQay0VhjZm/7MbBUNbqOAXNM6OGebXxVp6sHUAL
iBGY/Dls7B1TsWeGObE0sS1MXEpuREuloZjcsNVcNXWPlLdZtkSH6uwWzR0PyG/Z
+ZXfNodZtd/voKlvLOw5B3opGIFaLkbtLZQwMiGtl42AS89lZg==
-----END ENCRYPTED PRIVATE KEY-----
`

func TestParseFFCscryptPrivateKey(t *testing.T) {
	keyList := []struct {
		name      string
		clear     string
		encrypted string
		password  string
	}{
		{
			name:      "encryptedRFCscrypt",
			clear:     "",
			encrypted: encryptedRFCscrypt,
			password:  "Rabbit",
		},
	}
	for i, key := range keyList {
		t.Run(key.name, func(t *testing.T) {
			testParsePKCS8PrivateKey(t, i, &key)
		})
	}
}
