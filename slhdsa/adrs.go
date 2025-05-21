package slhdsa

type addressType byte

const (
	AddressTypeWOTSHash addressType = iota
	AddressTypeWOTSPK
	AddressTypeTree
	AddressTypeFORSTree
	AddressTypeFORSRoots
	AddressTypeWOTSPRF
	AddressTypeFORSPRF
)

type adrsOperations interface {
	setLayerAddress(l uint32)
	setTreeAddress(t uint64)
	setTypeAndClear(y addressType)
	setKeyPairAddress(i uint32)
	setChainAddress(i uint32)
	setHashAddress(i uint32)
	setTreeHeight(i uint32)
	setTreeIndex(i uint32)
	getKeyPairAddress() uint32
	getTreeIndex() uint32
	bytes() []byte
	clone(source adrsOperations)
	copyKeyPairAddress(source adrsOperations)
}

type adrs [32]byte

func (a *adrs) setLayerAddress(l uint32) {
	a[0] = byte(l >> 24)
	a[1] = byte(l >> 16)
	a[2] = byte(l >> 8)
	a[3] = byte(l)
}

func (a *adrs) setTreeAddress(t uint64) {
	a[4+4] = byte(t >> 56)
	a[4+5] = byte(t >> 48)
	a[4+6] = byte(t >> 40)
	a[4+7] = byte(t >> 32)
	a[4+8] = byte(t >> 24)
	a[4+9] = byte(t >> 16)
	a[4+10] = byte(t >> 8)
	a[4+11] = byte(t)
}

func (a *adrs) setTypeAndClear(y addressType) {
	a[19] = byte(y)
	clear(a[20:])
}

func (a *adrs) setKeyPairAddress(i uint32) {
	a[20] = byte(i >> 24)
	a[21] = byte(i >> 16)
	a[22] = byte(i >> 8)
	a[23] = byte(i)
}

func (a *adrs) setChainAddress(i uint32) {
	a[24] = byte(i >> 24)
	a[25] = byte(i >> 16)
	a[26] = byte(i >> 8)
	a[27] = byte(i)
}

func (a *adrs) setHashAddress(i uint32) {
	a[28] = byte(i >> 24)
	a[29] = byte(i >> 16)
	a[30] = byte(i >> 8)
	a[31] = byte(i)
}

func (a *adrs) setTreeHeight(i uint32) {
	a.setChainAddress(i)
}

func (a *adrs) setTreeIndex(i uint32) {
	a.setHashAddress(i)
}

func (a *adrs) getKeyPairAddress() uint32 {
	return uint32(a[20])<<24 | uint32(a[21])<<16 | uint32(a[22])<<8 | uint32(a[23])
}

func (a *adrs) getTreeIndex() uint32 {
	return uint32(a[28])<<24 | uint32(a[29])<<16 | uint32(a[30])<<8 | uint32(a[31])
}

func (a *adrs) bytes() []byte {
	return a[:]
}

func (a *adrs) clone(b adrsOperations) {
	copy(a[:], b.bytes())
}

func (a *adrs) copyKeyPairAddress(b adrsOperations) {
	copy(a[20:24], b.bytes()[20:24])
}

func newAdrs() adrsOperations {
	return &adrs{}
}

type adrsc [22]byte

func (a *adrsc) setLayerAddress(l uint32) {
	a[0] = byte(l)
}

func (a *adrsc) setTreeAddress(t uint64) {
	a[1] = byte(t >> 56)
	a[2] = byte(t >> 48)
	a[3] = byte(t >> 40)
	a[4] = byte(t >> 32)
	a[5] = byte(t >> 24)
	a[6] = byte(t >> 16)
	a[7] = byte(t >> 8)
	a[8] = byte(t)
}

func (a *adrsc) setTypeAndClear(y addressType) {
	a[9] = byte(y)
	clear(a[10:])
}

func (a *adrsc) setKeyPairAddress(i uint32) {
	a[10] = byte(i >> 24)
	a[11] = byte(i >> 16)
	a[12] = byte(i >> 8)
	a[13] = byte(i)
}

func (a *adrsc) setChainAddress(i uint32) {
	a[14] = byte(i >> 24)
	a[15] = byte(i >> 16)
	a[16] = byte(i >> 8)
	a[17] = byte(i)
}

func (a *adrsc) setHashAddress(i uint32) {
	a[18] = byte(i >> 24)
	a[19] = byte(i >> 16)
	a[20] = byte(i >> 8)
	a[21] = byte(i)
}

func (a *adrsc) setTreeHeight(i uint32) {
	a.setChainAddress(i)
}

func (a *adrsc) setTreeIndex(i uint32) {
	a.setHashAddress(i)
}

func (a *adrsc) getKeyPairAddress() uint32 {
	return uint32(a[10])<<24 | uint32(a[11])<<16 | uint32(a[12])<<8 | uint32(a[13])
}

func (a *adrsc) getTreeIndex() uint32 {
	return uint32(a[18])<<24 | uint32(a[19])<<16 | uint32(a[20])<<8 | uint32(a[21])
}

func (a *adrsc) bytes() []byte {
	return a[:]
}

func (a *adrsc) clone(b adrsOperations) {
	copy(a[:], b.bytes())
}

func (a *adrsc) copyKeyPairAddress(b adrsOperations) {
	copy(a[10:14], b.bytes()[10:14])
}

func newAdrsC() adrsOperations {
	return &adrsc{}
}
