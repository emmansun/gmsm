package smx509

// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/var/ssl/certs/ca-bundle.crt",
}

// Possible directories with certificate files; all will be read.
var certDirectories = []string{
	"/var/ssl/certs",
}
