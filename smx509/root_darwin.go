package smx509

//
// We DO NOT support system verify on darwin due to complex internal package dependencies.
//
func (c *Certificate) systemVerify(opts *VerifyOptions) (chains [][]*Certificate, err error) {
	return nil, nil
}

func loadSystemRoots() (*CertPool, error) {
	return &CertPool{systemPool: true}, nil
}
