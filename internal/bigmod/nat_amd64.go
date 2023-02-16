//go:build amd64 && gc && !purego
// +build amd64,gc,!purego

package bigmod

//go:noescape
func montgomeryLoop(d []uint, a []uint, b []uint, m []uint, m0inv uint) uint
