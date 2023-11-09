//go:build dragonfly || freebsd || netbsd || openbsd

package smx509

// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/usr/local/etc/ssl/cert.pem",            // FreeBSD
	"/etc/ssl/cert.pem",                      // OpenBSD
	"/usr/local/share/certs/ca-root-nss.crt", // DragonFly
	"/etc/openssl/certs/ca-certificates.crt", // NetBSD
}

// Possible directories with certificate files; all will be read.
var certDirectories = []string{
	"/etc/ssl/certs",         // FreeBSD 12.2+
	"/usr/local/share/certs", // FreeBSD
	"/etc/openssl/certs",     // NetBSD
}
