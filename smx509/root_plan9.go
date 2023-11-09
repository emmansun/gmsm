//go:build plan9

package smx509

import (
	"os"
)

// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/sys/lib/tls/ca.pem",
}

func (c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err error) {
	return nil, nil
}

func loadSystemRoots() (*CertPool, error) {
	roots := NewCertPool()
	var bestErr error
	for _, file := range certFiles {
		data, err := os.ReadFile(file)
		if err == nil {
			roots.AppendCertsFromPEM(data)
			return roots, nil
		}
		if bestErr == nil || (os.IsNotExist(bestErr) && !os.IsNotExist(err)) {
			bestErr = err
		}
	}
	if bestErr == nil {
		return roots, nil
	}
	return nil, bestErr
}
