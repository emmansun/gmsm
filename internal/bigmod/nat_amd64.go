//go:build amd64 && gc && !purego
// +build amd64,gc,!purego

package bigmod

func montgomeryLoop(d []uint, a []uint, b []uint, m []uint, m0inv uint) uint
