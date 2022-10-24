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

const encryptedSM9SignMasterPrivateKey = `-----BEGIN ENCRYPTED SM9 SIGN MASTER KEY-----
MIIBNjBhBgkqhkiG9w0BBQ0wVDA0BgkqhkiG9w0BBQwwJwQQuRb0v3wC0mAANvym
YLiNSAIDAQAAAgEQMAsGCSqBHM9VAYMRAjAcBggqgRzPVQFoAgQQuzlPtraTjW+9
EpGFcss7TgSB0KnwoVMBPUFcZEqiH1DPFZVqHcbdfmZheeIXCdeS5cYGL7Cg6Ohd
YZe9LWCFNBAvJz6zxeJGiaeR3VW5QDB+jPtSYIu9ET85yFsaohLt/ZNdgdGec2s6
rmG5/ufL+9LtprtWF4BcbwTCCPr6mX3Tvq+Xacw0YY9VHcpUDOUHGwkdhea82M5D
nUCi5FhiNKDe4Qfp7HG597FlK9Vwy5Nn5xRKsfoG2JJuQYZkqmORFJA/aQQq/ejD
NbR0XajuWC9+bMq3SeEyT6Je0aEeHuOfKFw=
-----END ENCRYPTED SM9 SIGN MASTER KEY-----
`

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

const encryptedSM9EncMasterPrivateKey = `-----BEGIN ENCRYPTED SM9 ENC MASTER KEY-----
MIH2MGEGCSqGSIb3DQEFDTBUMDQGCSqGSIb3DQEFDDAnBBAjXv966WmKuBfUH1Bq
OMwUAgMBAAACARAwCwYJKoEcz1UBgxECMBwGCCqBHM9VAWgCBBAtVvud0awyXO1r
dz92Pn+9BIGQlAsGegoSrApDm+rbszu1wsUwAVbq+EtgkraBSZRqGYByBOSN9G9m
p0lZJ75/TJMqRunkUhAUorNzXkdy2nab1VRs+Y8lKzhw5Y7KLnjbRsoDEPcvluSW
UVHgVDiaGKLKlKWTdhRRzLnBOocE0LA3FnOH86eUFjGY87ss6vz8iD9JHHfap4yr
Yut8eao1nBSY
-----END ENCRYPTED SM9 ENC MASTER KEY-----
`

const encryptedSM9EncPrivateKey = `
-----BEGIN ENCRYPTED SM9 ENC PRIVATE KEY-----
MIIBVjBhBgkqhkiG9w0BBQ0wVDA0BgkqhkiG9w0BBQwwJwQQ7qFYth3lhEj9pHl4
V0HeiwIDAQAAAgEQMAsGCSqBHM9VAYMRAjAcBggqgRzPVQFoAgQQvk8cAqLQcGr1
LfRo8lz6TwSB8Ma6HVx/t1q+wbu+NLLzq1uok7zNBKM8Z9hFiqrY1pngZTtweVHP
w/r6inOU4rI9Eex6R7C4koT9cGYN4QBur3BHxTLPM7C4knldxxYHuA98MEGHMMcE
gJIcgZlrkdprvLSXqdKJ/Ee7Ut4SuJuMW/Ww0hTrOmnI0j4cRAaZAgEh9Lh9B5CK
tzO+xTcb9siTzgRDKxnsZB85c1pwzQ3LH1KNR7tsg1z/AW+Hab4+8WX7mIIlvmVM
zkRVx8ZgZCNo/MTFjw2qCNVsGrcj/xFm63p8eWoYGx6eXS6nr3IYRIDwR5F7CoNY
h1/9v+oJWBaPxQ==
-----END ENCRYPTED SM9 ENC PRIVATE KEY-----
`

func TestParseSM9PrivateKey(t *testing.T) {
	keyList := []testPrivateKey{
		{
			name:      "encryptedSM9SignMasterPrivateKey",
			clear:     "",
			encrypted: encryptedSM9SignMasterPrivateKey,
			password:  "123456",
		},
		{
			name:      "encryptedSM9SignPrivateKey",
			clear:     "",
			encrypted: encryptedSM9SignPrivateKey,
			password:  "123456",
		},
		{
			name:      "encryptedSM9EncMasterPrivateKey",
			clear:     "",
			encrypted: encryptedSM9EncMasterPrivateKey,
			password:  "123456",
		},
		{
			name:      "encryptedSM9EncPrivateKey",
			clear:     "",
			encrypted: encryptedSM9EncPrivateKey,
			password:  "123456",
		},
	}
	for i, key := range keyList {
		t.Run(key.name, func(t *testing.T) {
			testParsePKCS8PrivateKey(t, i, &key)
		})
	}
}
