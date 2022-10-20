package drbg

import (
	"time"
)

const DRBG_RESEED_COUNTER_INTERVAL_LEVEL2 uint64 = 1 << 10
const DRBG_RESEED_COUNTER_INTERVAL_LEVEL1 uint64 = 1 << 20
const DRBG_RESEED_TIME_INTERVAL_LEVEL2 = time.Duration(60) * time.Second
const DRBG_RESEED_TIME_INTERVAL_LEVEL1 = time.Duration(600) * time.Second
const MAX_BYTES = 1 << 27

type SecurityLevel byte

const (
	SECURITY_LEVEL_ONE SecurityLevel = 0x01
	SECURITY_LEVEL_TWO SecurityLevel = 0x02
)

// DRBG interface for both hash and ctr drbg implementations
type DRBG interface {
	// check internal state, return if reseed required
	NeedReseed() bool
	// reseed process
	Reseed(entropy, additional []byte) error
	// generate requrested bytes to b
	Generate(b, additional []byte) error
}

type BaseDrbg struct {
	v                       []byte
	seedLength              int
	reseedTime              time.Time
	reseedIntervalInTime    time.Duration
	reseedCounter           uint64
	reseedIntervalInCounter uint64
	securityLevel           SecurityLevel
	gm                      bool
}

func (hd *BaseDrbg) NeedReseed() bool {
	return (hd.reseedCounter > hd.reseedIntervalInCounter) || (hd.gm && time.Since(hd.reseedTime) > hd.reseedIntervalInTime)
}

func add(left, right []byte, len int) {
	var temp uint16 = 0
	for i := len - 1; i >= 0; i-- {
		temp += uint16(left[i]) + uint16(right[i])
		right[i] = byte(temp & 0xff)
		temp >>= 8
	}
}

func addOne(data []byte, len int) {
	var temp uint16 = 1
	for i := len - 1; i >= 0; i-- {
		temp += uint16(data[i])
		data[i] = byte(temp & 0xff)
		temp >>= 8
	}
}
