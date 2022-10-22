//go:build !race
// +build !race

package pkcs8_test

import (
	"testing"
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
	keyList := []testPrivateKey{
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

const encryptedSM9SignPrivateKey = `-----BEGIN ENCRYPTED SM9 SIGN PRIVATE KEY-----
MIIBVjBhBgkqhkiG9w0BBQ0wVDA0BgkqhkiG9w0BBQwwJwQQxWctHikJLVP2A7fQ
nm6qwQIDAQAAAgEQMAsGCSqBHM9VAYMRAjAcBggqgRzPVQFoAgQQfuWLjhO7iJNX
2owsXE8/6gSB8Ot4oMs97o7dDd6o2U29uTjvkt7Xq/ti/2OPoOvDeGr/SWTmLUHY
6X71SpB/GAmBVE1qMXSxFHotgeq1cbwuZtwqLV2GA0etAnC2MZV/2BYcx+qOwwgX
uljiXhlvpvxHfxxdL7HzJ5oC+AuMblQZnAvaicmS9Pr+EPk4gzusiCc4cu1q+sTh
xl4HzCz08DYx8l5j1B/FCnN0/9tv2F2Q6j3xWARFC8EJPAEhALdO+hol56Tz7A2a
zSK4N8ox4ip3G8L6TVMIlc8qFIfsnaVn+dQSWDubya8Lq4AieEs8mL+kPqEnSIUX
fYuup/MCEz2zpA==
-----END ENCRYPTED SM9 SIGN PRIVATE KEY-----
`

func TestParseSM9PrivateKey(t *testing.T) {
	keyList := []testPrivateKey{
		{
			name:      "encryptedSM9SignPrivateKey",
			clear:     "",
			encrypted: encryptedSM9SignPrivateKey,
			password:  "123456",
		},
	}
	for i, key := range keyList {
		t.Run(key.name, func(t *testing.T) {
			testParsePKCS8PrivateKey(t, i, &key)
		})
	}
}
