package smx509

import (
	"errors"
)

func (c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err error) {
	return nil, nil
}

func loadSystemRoots() (*CertPool, error) {
	return nil, errors.New("x509: gmsm does not support darwin system root yet")
}
