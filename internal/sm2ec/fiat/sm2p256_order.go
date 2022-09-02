package fiat

import (
	"errors"
	"math/bits"
)

var orderK0 uint64 = 0x327f9e8872350975

// SM2P256OrderElement is an integer modulo 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123.
//
// The zero value is a valid zero element.
type SM2P256OrderElement struct {
	// Values are represented internally always in the Montgomery domain, and
	// converted in Bytes and SetBytes.
	x sm2p256MontgomeryDomainFieldElement
}

// One sets e = 1, and returns e.
func (e *SM2P256OrderElement) One() *SM2P256OrderElement {
	e.x[0] = 0xac440bf6c62abedd
	e.x[1] = 0x8dfc2094de39fad4
	e.x[2] = uint64(0x0)
	e.x[3] = 0x100000000
	return e
}

// Add sets e = t1 + t2, and returns e.
func (e *SM2P256OrderElement) Add(t1, t2 *SM2P256OrderElement) *SM2P256OrderElement {
	var x1 uint64
	var x2 uint64
	x1, x2 = bits.Add64(t1.x[0], t2.x[0], uint64(0x0))
	var x3 uint64
	var x4 uint64
	x3, x4 = bits.Add64(t1.x[1], t2.x[1], uint64(sm2p256Uint1(x2)))
	var x5 uint64
	var x6 uint64
	x5, x6 = bits.Add64(t1.x[2], t2.x[2], uint64(sm2p256Uint1(x4)))
	var x7 uint64
	var x8 uint64
	x7, x8 = bits.Add64(t1.x[3], t2.x[3], uint64(sm2p256Uint1(x6)))
	var x9 uint64
	var x10 uint64
	x9, x10 = bits.Sub64(x1, 0x53bbf40939d54123, uint64(0x0))
	var x11 uint64
	var x12 uint64
	x11, x12 = bits.Sub64(x3, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x10)))
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Sub64(x5, 0xffffffffffffffff, uint64(sm2p256Uint1(x12)))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Sub64(x7, 0xfffffffeffffffff, uint64(sm2p256Uint1(x14)))
	var x18 uint64
	_, x18 = bits.Sub64(uint64(sm2p256Uint1(x8)), uint64(0x0), uint64(sm2p256Uint1(x16)))
	var x19 uint64
	sm2p256CmovznzU64(&x19, sm2p256Uint1(x18), x9, x1)
	var x20 uint64
	sm2p256CmovznzU64(&x20, sm2p256Uint1(x18), x11, x3)
	var x21 uint64
	sm2p256CmovznzU64(&x21, sm2p256Uint1(x18), x13, x5)
	var x22 uint64
	sm2p256CmovznzU64(&x22, sm2p256Uint1(x18), x15, x7)
	e.x[0] = x19
	e.x[1] = x20
	e.x[2] = x21
	e.x[3] = x22
	return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *SM2P256OrderElement) Sub(t1, t2 *SM2P256OrderElement) *SM2P256OrderElement {
	var x1 uint64
	var x2 uint64
	x1, x2 = bits.Sub64(t1.x[0], t2.x[0], uint64(0x0))
	var x3 uint64
	var x4 uint64
	x3, x4 = bits.Sub64(t1.x[1], t2.x[1], uint64(sm2p256Uint1(x2)))
	var x5 uint64
	var x6 uint64
	x5, x6 = bits.Sub64(t1.x[2], t2.x[2], uint64(sm2p256Uint1(x4)))
	var x7 uint64
	var x8 uint64
	x7, x8 = bits.Sub64(t1.x[3], t2.x[3], uint64(sm2p256Uint1(x6)))
	var x9 uint64
	sm2p256CmovznzU64(&x9, sm2p256Uint1(x8), uint64(0x0), 0xffffffffffffffff)
	var x10 uint64
	var x11 uint64
	x10, x11 = bits.Add64(x1, (x9 & 0x53bbf40939d54123), uint64(0x0))
	var x12 uint64
	var x13 uint64
	x12, x13 = bits.Add64(x3, (x9 & 0x7203df6b21c6052b), uint64(sm2p256Uint1(x11)))
	var x14 uint64
	var x15 uint64
	x14, x15 = bits.Add64(x5, x9, uint64(sm2p256Uint1(x13)))
	var x16 uint64
	x16, _ = bits.Add64(x7, (x9 & 0xfffffffeffffffff), uint64(sm2p256Uint1(x15)))
	e.x[0] = x10
	e.x[1] = x12
	e.x[2] = x14
	e.x[3] = x16
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *SM2P256OrderElement) Mul(t1, t2 *SM2P256OrderElement) *SM2P256OrderElement {
	x1 := t1.x[1]
	x2 := t1.x[2]
	x3 := t1.x[3]
	x4 := t1.x[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, t2.x[3])
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, t2.x[2])
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, t2.x[1])
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, t2.x[0])
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Add64(x12, x9, uint64(0x0))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x10, x7, uint64(sm2p256Uint1(x14)))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x8, x5, uint64(sm2p256Uint1(x16)))
	x19 := (uint64(sm2p256Uint1(x18)) + x6)
	var x20 uint64
	var x21 uint64
	_, y11 := bits.Mul64(x11, orderK0)
	x21, x20 = bits.Mul64(y11, 0xfffffffeffffffff)
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(y11, 0xffffffffffffffff)
	var x24 uint64
	var x25 uint64
	x25, x24 = bits.Mul64(y11, 0x7203df6b21c6052b)
	var x26 uint64
	var x27 uint64
	x27, x26 = bits.Mul64(y11, 0x53bbf40939d54123)
	var x28 uint64
	var x29 uint64
	x28, x29 = bits.Add64(x27, x24, uint64(0x0))
	var x30 uint64
	var x31 uint64
	x30, x31 = bits.Add64(x25, x22, uint64(sm2p256Uint1(x29)))
	var x32 uint64
	var x33 uint64
	x32, x33 = bits.Add64(x23, x20, uint64(sm2p256Uint1(x31)))
	x34 := (uint64(sm2p256Uint1(x33)) + x21)
	var x36 uint64
	_, x36 = bits.Add64(x11, x26, uint64(0x0))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x13, x28, uint64(sm2p256Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x15, x30, uint64(sm2p256Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64(x17, x32, uint64(sm2p256Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x43, x44 = bits.Add64(x19, x34, uint64(sm2p256Uint1(x42)))
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(x1, t2.x[3])
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, t2.x[2])
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, t2.x[1])
	var x51 uint64
	var x52 uint64
	x52, x51 = bits.Mul64(x1, t2.x[0])
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x52, x49, uint64(0x0))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x50, x47, uint64(sm2p256Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(x48, x45, uint64(sm2p256Uint1(x56)))
	x59 := (uint64(sm2p256Uint1(x58)) + x46)
	var x60 uint64
	var x61 uint64
	x60, x61 = bits.Add64(x37, x51, uint64(0x0))
	var x62 uint64
	var x63 uint64
	x62, x63 = bits.Add64(x39, x53, uint64(sm2p256Uint1(x61)))
	var x64 uint64
	var x65 uint64
	x64, x65 = bits.Add64(x41, x55, uint64(sm2p256Uint1(x63)))
	var x66 uint64
	var x67 uint64
	x66, x67 = bits.Add64(x43, x57, uint64(sm2p256Uint1(x65)))
	var x68 uint64
	var x69 uint64
	x68, x69 = bits.Add64(uint64(sm2p256Uint1(x44)), x59, uint64(sm2p256Uint1(x67)))
	var x70 uint64
	var x71 uint64
	_, y60 := bits.Mul64(x60, orderK0)
	x71, x70 = bits.Mul64(y60, 0xfffffffeffffffff)
	var x72 uint64
	var x73 uint64
	x73, x72 = bits.Mul64(y60, 0xffffffffffffffff)
	var x74 uint64
	var x75 uint64
	x75, x74 = bits.Mul64(y60, 0x7203df6b21c6052b)
	var x76 uint64
	var x77 uint64
	x77, x76 = bits.Mul64(y60, 0x53bbf40939d54123)
	var x78 uint64
	var x79 uint64
	x78, x79 = bits.Add64(x77, x74, uint64(0x0))
	var x80 uint64
	var x81 uint64
	x80, x81 = bits.Add64(x75, x72, uint64(sm2p256Uint1(x79)))
	var x82 uint64
	var x83 uint64
	x82, x83 = bits.Add64(x73, x70, uint64(sm2p256Uint1(x81)))
	x84 := (uint64(sm2p256Uint1(x83)) + x71)
	var x86 uint64
	_, x86 = bits.Add64(x60, x76, uint64(0x0))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(x62, x78, uint64(sm2p256Uint1(x86)))
	var x89 uint64
	var x90 uint64
	x89, x90 = bits.Add64(x64, x80, uint64(sm2p256Uint1(x88)))
	var x91 uint64
	var x92 uint64
	x91, x92 = bits.Add64(x66, x82, uint64(sm2p256Uint1(x90)))
	var x93 uint64
	var x94 uint64
	x93, x94 = bits.Add64(x68, x84, uint64(sm2p256Uint1(x92)))
	x95 := (uint64(sm2p256Uint1(x94)) + uint64(sm2p256Uint1(x69)))
	var x96 uint64
	var x97 uint64
	x97, x96 = bits.Mul64(x2, t2.x[3])
	var x98 uint64
	var x99 uint64
	x99, x98 = bits.Mul64(x2, t2.x[2])
	var x100 uint64
	var x101 uint64
	x101, x100 = bits.Mul64(x2, t2.x[1])
	var x102 uint64
	var x103 uint64
	x103, x102 = bits.Mul64(x2, t2.x[0])
	var x104 uint64
	var x105 uint64
	x104, x105 = bits.Add64(x103, x100, uint64(0x0))
	var x106 uint64
	var x107 uint64
	x106, x107 = bits.Add64(x101, x98, uint64(sm2p256Uint1(x105)))
	var x108 uint64
	var x109 uint64
	x108, x109 = bits.Add64(x99, x96, uint64(sm2p256Uint1(x107)))
	x110 := (uint64(sm2p256Uint1(x109)) + x97)
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Add64(x87, x102, uint64(0x0))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Add64(x89, x104, uint64(sm2p256Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Add64(x91, x106, uint64(sm2p256Uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x93, x108, uint64(sm2p256Uint1(x116)))
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x95, x110, uint64(sm2p256Uint1(x118)))
	var x121 uint64
	var x122 uint64
	_, y111 := bits.Mul64(x111, orderK0)
	x122, x121 = bits.Mul64(y111, 0xfffffffeffffffff)
	var x123 uint64
	var x124 uint64
	x124, x123 = bits.Mul64(y111, 0xffffffffffffffff)
	var x125 uint64
	var x126 uint64
	x126, x125 = bits.Mul64(y111, 0x7203df6b21c6052b)
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(y111, 0x53bbf40939d54123)
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x128, x125, uint64(0x0))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x126, x123, uint64(sm2p256Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(x124, x121, uint64(sm2p256Uint1(x132)))
	x135 := (uint64(sm2p256Uint1(x134)) + x122)
	var x137 uint64
	_, x137 = bits.Add64(x111, x127, uint64(0x0))
	var x138 uint64
	var x139 uint64
	x138, x139 = bits.Add64(x113, x129, uint64(sm2p256Uint1(x137)))
	var x140 uint64
	var x141 uint64
	x140, x141 = bits.Add64(x115, x131, uint64(sm2p256Uint1(x139)))
	var x142 uint64
	var x143 uint64
	x142, x143 = bits.Add64(x117, x133, uint64(sm2p256Uint1(x141)))
	var x144 uint64
	var x145 uint64
	x144, x145 = bits.Add64(x119, x135, uint64(sm2p256Uint1(x143)))
	x146 := (uint64(sm2p256Uint1(x145)) + uint64(sm2p256Uint1(x120)))
	var x147 uint64
	var x148 uint64
	x148, x147 = bits.Mul64(x3, t2.x[3])
	var x149 uint64
	var x150 uint64
	x150, x149 = bits.Mul64(x3, t2.x[2])
	var x151 uint64
	var x152 uint64
	x152, x151 = bits.Mul64(x3, t2.x[1])
	var x153 uint64
	var x154 uint64
	x154, x153 = bits.Mul64(x3, t2.x[0])
	var x155 uint64
	var x156 uint64
	x155, x156 = bits.Add64(x154, x151, uint64(0x0))
	var x157 uint64
	var x158 uint64
	x157, x158 = bits.Add64(x152, x149, uint64(sm2p256Uint1(x156)))
	var x159 uint64
	var x160 uint64
	x159, x160 = bits.Add64(x150, x147, uint64(sm2p256Uint1(x158)))
	x161 := (uint64(sm2p256Uint1(x160)) + x148)
	var x162 uint64
	var x163 uint64
	x162, x163 = bits.Add64(x138, x153, uint64(0x0))
	var x164 uint64
	var x165 uint64
	x164, x165 = bits.Add64(x140, x155, uint64(sm2p256Uint1(x163)))
	var x166 uint64
	var x167 uint64
	x166, x167 = bits.Add64(x142, x157, uint64(sm2p256Uint1(x165)))
	var x168 uint64
	var x169 uint64
	x168, x169 = bits.Add64(x144, x159, uint64(sm2p256Uint1(x167)))
	var x170 uint64
	var x171 uint64
	x170, x171 = bits.Add64(x146, x161, uint64(sm2p256Uint1(x169)))
	var x172 uint64
	var x173 uint64
	_, y162 := bits.Mul64(x162, orderK0)
	x173, x172 = bits.Mul64(y162, 0xfffffffeffffffff)
	var x174 uint64
	var x175 uint64
	x175, x174 = bits.Mul64(y162, 0xffffffffffffffff)
	var x176 uint64
	var x177 uint64
	x177, x176 = bits.Mul64(y162, 0x7203df6b21c6052b)
	var x178 uint64
	var x179 uint64
	x179, x178 = bits.Mul64(y162, 0x53bbf40939d54123)
	var x180 uint64
	var x181 uint64
	x180, x181 = bits.Add64(x179, x176, uint64(0x0))
	var x182 uint64
	var x183 uint64
	x182, x183 = bits.Add64(x177, x174, uint64(sm2p256Uint1(x181)))
	var x184 uint64
	var x185 uint64
	x184, x185 = bits.Add64(x175, x172, uint64(sm2p256Uint1(x183)))
	x186 := (uint64(sm2p256Uint1(x185)) + x173)
	var x188 uint64
	_, x188 = bits.Add64(x162, x178, uint64(0x0))
	var x189 uint64
	var x190 uint64
	x189, x190 = bits.Add64(x164, x180, uint64(sm2p256Uint1(x188)))
	var x191 uint64
	var x192 uint64
	x191, x192 = bits.Add64(x166, x182, uint64(sm2p256Uint1(x190)))
	var x193 uint64
	var x194 uint64
	x193, x194 = bits.Add64(x168, x184, uint64(sm2p256Uint1(x192)))
	var x195 uint64
	var x196 uint64
	x195, x196 = bits.Add64(x170, x186, uint64(sm2p256Uint1(x194)))
	x197 := (uint64(sm2p256Uint1(x196)) + uint64(sm2p256Uint1(x171)))
	var x198 uint64
	var x199 uint64
	x198, x199 = bits.Sub64(x189, 0x53bbf40939d54123, uint64(0x0))
	var x200 uint64
	var x201 uint64
	x200, x201 = bits.Sub64(x191, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x199)))
	var x202 uint64
	var x203 uint64
	x202, x203 = bits.Sub64(x193, 0xffffffffffffffff, uint64(sm2p256Uint1(x201)))
	var x204 uint64
	var x205 uint64
	x204, x205 = bits.Sub64(x195, 0xfffffffeffffffff, uint64(sm2p256Uint1(x203)))
	var x207 uint64
	_, x207 = bits.Sub64(x197, uint64(0x0), uint64(sm2p256Uint1(x205)))
	var x208 uint64
	sm2p256CmovznzU64(&x208, sm2p256Uint1(x207), x198, x189)
	var x209 uint64
	sm2p256CmovznzU64(&x209, sm2p256Uint1(x207), x200, x191)
	var x210 uint64
	sm2p256CmovznzU64(&x210, sm2p256Uint1(x207), x202, x193)
	var x211 uint64
	sm2p256CmovznzU64(&x211, sm2p256Uint1(x207), x204, x195)
	e.x[0] = x208
	e.x[1] = x209
	e.x[2] = x210
	e.x[3] = x211

	return e
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *SM2P256OrderElement) Select(a, b *SM2P256OrderElement, cond int) *SM2P256OrderElement {
	sm2p256Selectznz((*sm2p256UntypedFieldElement)(&v.x), sm2p256Uint1(cond),
		(*sm2p256UntypedFieldElement)(&b.x), (*sm2p256UntypedFieldElement)(&a.x))
	return v
}

// Square sets e = t * t, and returns e.
func (e *SM2P256OrderElement) Square(t *SM2P256OrderElement) *SM2P256OrderElement {
	x1 := t.x[1]
	x2 := t.x[2]
	x3 := t.x[3]
	x4 := t.x[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, t.x[3])
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, t.x[2])
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, t.x[1])
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, t.x[0])
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Add64(x12, x9, uint64(0x0))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x10, x7, uint64(sm2p256Uint1(x14)))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x8, x5, uint64(sm2p256Uint1(x16)))
	x19 := (uint64(sm2p256Uint1(x18)) + x6)
	var x20 uint64
	var x21 uint64
	_, y11 := bits.Mul64(x11, orderK0)
	x21, x20 = bits.Mul64(y11, 0xfffffffeffffffff)
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(y11, 0xffffffffffffffff)
	var x24 uint64
	var x25 uint64
	x25, x24 = bits.Mul64(y11, 0x7203df6b21c6052b)
	var x26 uint64
	var x27 uint64
	x27, x26 = bits.Mul64(y11, 0x53bbf40939d54123)
	var x28 uint64
	var x29 uint64
	x28, x29 = bits.Add64(x27, x24, uint64(0x0))
	var x30 uint64
	var x31 uint64
	x30, x31 = bits.Add64(x25, x22, uint64(sm2p256Uint1(x29)))
	var x32 uint64
	var x33 uint64
	x32, x33 = bits.Add64(x23, x20, uint64(sm2p256Uint1(x31)))
	x34 := (uint64(sm2p256Uint1(x33)) + x21)
	var x36 uint64
	_, x36 = bits.Add64(x11, x26, uint64(0x0))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x13, x28, uint64(sm2p256Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x15, x30, uint64(sm2p256Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64(x17, x32, uint64(sm2p256Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x43, x44 = bits.Add64(x19, x34, uint64(sm2p256Uint1(x42)))
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(x1, t.x[3])
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, t.x[2])
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, t.x[1])
	var x51 uint64
	var x52 uint64
	x52, x51 = bits.Mul64(x1, t.x[0])
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x52, x49, uint64(0x0))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x50, x47, uint64(sm2p256Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(x48, x45, uint64(sm2p256Uint1(x56)))
	x59 := (uint64(sm2p256Uint1(x58)) + x46)
	var x60 uint64
	var x61 uint64
	x60, x61 = bits.Add64(x37, x51, uint64(0x0))
	var x62 uint64
	var x63 uint64
	x62, x63 = bits.Add64(x39, x53, uint64(sm2p256Uint1(x61)))
	var x64 uint64
	var x65 uint64
	x64, x65 = bits.Add64(x41, x55, uint64(sm2p256Uint1(x63)))
	var x66 uint64
	var x67 uint64
	x66, x67 = bits.Add64(x43, x57, uint64(sm2p256Uint1(x65)))
	var x68 uint64
	var x69 uint64
	x68, x69 = bits.Add64(uint64(sm2p256Uint1(x44)), x59, uint64(sm2p256Uint1(x67)))
	var x70 uint64
	var x71 uint64
	_, y60 := bits.Mul64(x60, orderK0)
	x71, x70 = bits.Mul64(y60, 0xfffffffeffffffff)
	var x72 uint64
	var x73 uint64
	x73, x72 = bits.Mul64(y60, 0xffffffffffffffff)
	var x74 uint64
	var x75 uint64
	x75, x74 = bits.Mul64(y60, 0x7203df6b21c6052b)
	var x76 uint64
	var x77 uint64
	x77, x76 = bits.Mul64(y60, 0x53bbf40939d54123)
	var x78 uint64
	var x79 uint64
	x78, x79 = bits.Add64(x77, x74, uint64(0x0))
	var x80 uint64
	var x81 uint64
	x80, x81 = bits.Add64(x75, x72, uint64(sm2p256Uint1(x79)))
	var x82 uint64
	var x83 uint64
	x82, x83 = bits.Add64(x73, x70, uint64(sm2p256Uint1(x81)))
	x84 := (uint64(sm2p256Uint1(x83)) + x71)
	var x86 uint64
	_, x86 = bits.Add64(x60, x76, uint64(0x0))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(x62, x78, uint64(sm2p256Uint1(x86)))
	var x89 uint64
	var x90 uint64
	x89, x90 = bits.Add64(x64, x80, uint64(sm2p256Uint1(x88)))
	var x91 uint64
	var x92 uint64
	x91, x92 = bits.Add64(x66, x82, uint64(sm2p256Uint1(x90)))
	var x93 uint64
	var x94 uint64
	x93, x94 = bits.Add64(x68, x84, uint64(sm2p256Uint1(x92)))
	x95 := (uint64(sm2p256Uint1(x94)) + uint64(sm2p256Uint1(x69)))
	var x96 uint64
	var x97 uint64
	x97, x96 = bits.Mul64(x2, t.x[3])
	var x98 uint64
	var x99 uint64
	x99, x98 = bits.Mul64(x2, t.x[2])
	var x100 uint64
	var x101 uint64
	x101, x100 = bits.Mul64(x2, t.x[1])
	var x102 uint64
	var x103 uint64
	x103, x102 = bits.Mul64(x2, t.x[0])
	var x104 uint64
	var x105 uint64
	x104, x105 = bits.Add64(x103, x100, uint64(0x0))
	var x106 uint64
	var x107 uint64
	x106, x107 = bits.Add64(x101, x98, uint64(sm2p256Uint1(x105)))
	var x108 uint64
	var x109 uint64
	x108, x109 = bits.Add64(x99, x96, uint64(sm2p256Uint1(x107)))
	x110 := (uint64(sm2p256Uint1(x109)) + x97)
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Add64(x87, x102, uint64(0x0))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Add64(x89, x104, uint64(sm2p256Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Add64(x91, x106, uint64(sm2p256Uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x93, x108, uint64(sm2p256Uint1(x116)))
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x95, x110, uint64(sm2p256Uint1(x118)))
	var x121 uint64
	var x122 uint64
	_, y111 := bits.Mul64(x111, orderK0)
	x122, x121 = bits.Mul64(y111, 0xfffffffeffffffff)
	var x123 uint64
	var x124 uint64
	x124, x123 = bits.Mul64(y111, 0xffffffffffffffff)
	var x125 uint64
	var x126 uint64
	x126, x125 = bits.Mul64(y111, 0x7203df6b21c6052b)
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(y111, 0x53bbf40939d54123)
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x128, x125, uint64(0x0))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x126, x123, uint64(sm2p256Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(x124, x121, uint64(sm2p256Uint1(x132)))
	x135 := (uint64(sm2p256Uint1(x134)) + x122)
	var x137 uint64
	_, x137 = bits.Add64(x111, x127, uint64(0x0))
	var x138 uint64
	var x139 uint64
	x138, x139 = bits.Add64(x113, x129, uint64(sm2p256Uint1(x137)))
	var x140 uint64
	var x141 uint64
	x140, x141 = bits.Add64(x115, x131, uint64(sm2p256Uint1(x139)))
	var x142 uint64
	var x143 uint64
	x142, x143 = bits.Add64(x117, x133, uint64(sm2p256Uint1(x141)))
	var x144 uint64
	var x145 uint64
	x144, x145 = bits.Add64(x119, x135, uint64(sm2p256Uint1(x143)))
	x146 := (uint64(sm2p256Uint1(x145)) + uint64(sm2p256Uint1(x120)))
	var x147 uint64
	var x148 uint64
	x148, x147 = bits.Mul64(x3, t.x[3])
	var x149 uint64
	var x150 uint64
	x150, x149 = bits.Mul64(x3, t.x[2])
	var x151 uint64
	var x152 uint64
	x152, x151 = bits.Mul64(x3, t.x[1])
	var x153 uint64
	var x154 uint64
	x154, x153 = bits.Mul64(x3, t.x[0])
	var x155 uint64
	var x156 uint64
	x155, x156 = bits.Add64(x154, x151, uint64(0x0))
	var x157 uint64
	var x158 uint64
	x157, x158 = bits.Add64(x152, x149, uint64(sm2p256Uint1(x156)))
	var x159 uint64
	var x160 uint64
	x159, x160 = bits.Add64(x150, x147, uint64(sm2p256Uint1(x158)))
	x161 := (uint64(sm2p256Uint1(x160)) + x148)
	var x162 uint64
	var x163 uint64
	x162, x163 = bits.Add64(x138, x153, uint64(0x0))
	var x164 uint64
	var x165 uint64
	x164, x165 = bits.Add64(x140, x155, uint64(sm2p256Uint1(x163)))
	var x166 uint64
	var x167 uint64
	x166, x167 = bits.Add64(x142, x157, uint64(sm2p256Uint1(x165)))
	var x168 uint64
	var x169 uint64
	x168, x169 = bits.Add64(x144, x159, uint64(sm2p256Uint1(x167)))
	var x170 uint64
	var x171 uint64
	x170, x171 = bits.Add64(x146, x161, uint64(sm2p256Uint1(x169)))
	var x172 uint64
	var x173 uint64
	_, y162 := bits.Mul64(x162, orderK0)
	x173, x172 = bits.Mul64(y162, 0xfffffffeffffffff)
	var x174 uint64
	var x175 uint64
	x175, x174 = bits.Mul64(y162, 0xffffffffffffffff)
	var x176 uint64
	var x177 uint64
	x177, x176 = bits.Mul64(y162, 0x7203df6b21c6052b)
	var x178 uint64
	var x179 uint64
	x179, x178 = bits.Mul64(y162, 0x53bbf40939d54123)
	var x180 uint64
	var x181 uint64
	x180, x181 = bits.Add64(x179, x176, uint64(0x0))
	var x182 uint64
	var x183 uint64
	x182, x183 = bits.Add64(x177, x174, uint64(sm2p256Uint1(x181)))
	var x184 uint64
	var x185 uint64
	x184, x185 = bits.Add64(x175, x172, uint64(sm2p256Uint1(x183)))
	x186 := (uint64(sm2p256Uint1(x185)) + x173)
	var x188 uint64
	_, x188 = bits.Add64(x162, x178, uint64(0x0))
	var x189 uint64
	var x190 uint64
	x189, x190 = bits.Add64(x164, x180, uint64(sm2p256Uint1(x188)))
	var x191 uint64
	var x192 uint64
	x191, x192 = bits.Add64(x166, x182, uint64(sm2p256Uint1(x190)))
	var x193 uint64
	var x194 uint64
	x193, x194 = bits.Add64(x168, x184, uint64(sm2p256Uint1(x192)))
	var x195 uint64
	var x196 uint64
	x195, x196 = bits.Add64(x170, x186, uint64(sm2p256Uint1(x194)))
	x197 := (uint64(sm2p256Uint1(x196)) + uint64(sm2p256Uint1(x171)))
	var x198 uint64
	var x199 uint64
	x198, x199 = bits.Sub64(x189, 0x53bbf40939d54123, uint64(0x0))
	var x200 uint64
	var x201 uint64
	x200, x201 = bits.Sub64(x191, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x199)))
	var x202 uint64
	var x203 uint64
	x202, x203 = bits.Sub64(x193, 0xffffffffffffffff, uint64(sm2p256Uint1(x201)))
	var x204 uint64
	var x205 uint64
	x204, x205 = bits.Sub64(x195, 0xfffffffeffffffff, uint64(sm2p256Uint1(x203)))
	var x207 uint64
	_, x207 = bits.Sub64(x197, uint64(0x0), uint64(sm2p256Uint1(x205)))
	var x208 uint64
	sm2p256CmovznzU64(&x208, sm2p256Uint1(x207), x198, x189)
	var x209 uint64
	sm2p256CmovznzU64(&x209, sm2p256Uint1(x207), x200, x191)
	var x210 uint64
	sm2p256CmovznzU64(&x210, sm2p256Uint1(x207), x202, x193)
	var x211 uint64
	sm2p256CmovznzU64(&x211, sm2p256Uint1(x207), x204, x195)
	e.x[0] = x208
	e.x[1] = x209
	e.x[2] = x210
	e.x[3] = x211

	return e
}

// SetBytes sets e = v, where v is a big-endian 32-byte encoding, and returns e.
// If v is not 32 bytes or it encodes a value higher than 2^256 - 2^224 - 2^96 + 2^64 - 1,
// SetBytes returns nil and an error, and e is unchanged.
func (e *SM2P256OrderElement) SetBytes(v []byte) (*SM2P256OrderElement, error) {
	if len(v) != sm2p256ElementLen {
		return nil, errors.New("invalid SM2P256OrderElement encoding")
	}
/*
	// Check for non-canonical encodings (p + k, 2p + k, etc.) by comparing to
	// the encoding of -1 mod p, so p - 1, the highest canonical encoding.
	var minusOneEncoding = new(SM2P256OrderElement).Sub(
		new(SM2P256OrderElement), new(SM2P256OrderElement).One()).Bytes()
	for i := range v {
		if v[i] < minusOneEncoding[i] {
			break
		}
		if v[i] > minusOneEncoding[i] {
			return nil, errors.New("invalid SM2P256OrderElement encoding")
		}
	}
*/
	var in [sm2p256ElementLen]byte
	copy(in[:], v)
	sm2p256InvertEndianness(in[:])
	var tmp sm2p256NonMontgomeryDomainFieldElement
	sm2p256FromBytes((*sm2p256UntypedFieldElement)(&tmp), &in)
	sm2p256OrderToMontgomery(&e.x, &tmp)
	return e, nil
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *SM2P256OrderElement) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [sm2p256ElementLen]byte
	return e.bytes(&out)
}

func (e *SM2P256OrderElement) bytes(out *[sm2p256ElementLen]byte) []byte {
	var tmp sm2p256NonMontgomeryDomainFieldElement
	sm2p256OrderFromMontgomery(&tmp, &e.x)
	sm2p256ToBytes(out, (*sm2p256UntypedFieldElement)(&tmp))
	sm2p256InvertEndianness(out[:])
	return out[:]
}

// sm2p256OrderFromMontgomery translates a field element out of the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
// Postconditions:
//   eval out1 mod m = (eval arg1 * ((2^64)⁻¹ mod m)^4) mod m
//   0 ≤ eval out1 < m
//
func sm2p256OrderFromMontgomery(out1 *sm2p256NonMontgomeryDomainFieldElement, arg1 *sm2p256MontgomeryDomainFieldElement) {
	x1 := arg1[0]
	_, y1 := bits.Mul64(arg1[0], orderK0)
	var x2 uint64
	var x3 uint64
	x3, x2 = bits.Mul64(y1, 0xfffffffeffffffff)
	var x4 uint64
	var x5 uint64
	x5, x4 = bits.Mul64(y1, 0xffffffffffffffff)
	var x6 uint64
	var x7 uint64
	x7, x6 = bits.Mul64(y1, 0x7203df6b21c6052b)
	var x8 uint64
	var x9 uint64
	x9, x8 = bits.Mul64(y1, 0x53bbf40939d54123)
	var x10 uint64
	var x11 uint64
	x10, x11 = bits.Add64(x9, x6, uint64(0x0))
	var x12 uint64
	var x13 uint64
	x12, x13 = bits.Add64(x7, x4, uint64(sm2p256Uint1(x11)))
	var x14 uint64
	var x15 uint64
	x14, x15 = bits.Add64(x5, x2, uint64(sm2p256Uint1(x13)))
	var x17 uint64
	_, x17 = bits.Add64(x1, x8, uint64(0x0))
	var x18 uint64
	var x19 uint64
	x18, x19 = bits.Add64(uint64(0x0), x10, uint64(sm2p256Uint1(x17)))
	var x20 uint64
	var x21 uint64
	x20, x21 = bits.Add64(uint64(0x0), x12, uint64(sm2p256Uint1(x19)))
	var x22 uint64
	var x23 uint64
	x22, x23 = bits.Add64(uint64(0x0), x14, uint64(sm2p256Uint1(x21)))
	var x24 uint64
	var x25 uint64
	x24, x25 = bits.Add64(x18, arg1[1], uint64(0x0))
	var x26 uint64
	var x27 uint64
	x26, x27 = bits.Add64(x20, uint64(0x0), uint64(sm2p256Uint1(x25)))
	var x28 uint64
	var x29 uint64
	x28, x29 = bits.Add64(x22, uint64(0x0), uint64(sm2p256Uint1(x27)))
	var x30 uint64
	var x31 uint64
	_, y24 := bits.Mul64(x24, orderK0)
	x31, x30 = bits.Mul64(y24, 0xfffffffeffffffff)
	var x32 uint64
	var x33 uint64
	x33, x32 = bits.Mul64(y24, 0xffffffffffffffff)
	var x34 uint64
	var x35 uint64
	x35, x34 = bits.Mul64(y24, 0x7203df6b21c6052b)
	var x36 uint64
	var x37 uint64
	x37, x36 = bits.Mul64(y24, 0x53bbf40939d54123)
	var x38 uint64
	var x39 uint64
	x38, x39 = bits.Add64(x37, x34, uint64(0x0))
	var x40 uint64
	var x41 uint64
	x40, x41 = bits.Add64(x35, x32, uint64(sm2p256Uint1(x39)))
	var x42 uint64
	var x43 uint64
	x42, x43 = bits.Add64(x33, x30, uint64(sm2p256Uint1(x41)))
	var x45 uint64
	_, x45 = bits.Add64(x24, x36, uint64(0x0))
	var x46 uint64
	var x47 uint64
	x46, x47 = bits.Add64(x26, x38, uint64(sm2p256Uint1(x45)))
	var x48 uint64
	var x49 uint64
	x48, x49 = bits.Add64(x28, x40, uint64(sm2p256Uint1(x47)))
	var x50 uint64
	var x51 uint64
	x50, x51 = bits.Add64((uint64(sm2p256Uint1(x29)) + (uint64(sm2p256Uint1(x23)) + (uint64(sm2p256Uint1(x15)) + x3))), x42, uint64(sm2p256Uint1(x49)))
	var x52 uint64
	var x53 uint64
	x52, x53 = bits.Add64(x46, arg1[2], uint64(0x0))
	var x54 uint64
	var x55 uint64
	x54, x55 = bits.Add64(x48, uint64(0x0), uint64(sm2p256Uint1(x53)))
	var x56 uint64
	var x57 uint64
	x56, x57 = bits.Add64(x50, uint64(0x0), uint64(sm2p256Uint1(x55)))
	var x58 uint64
	var x59 uint64
	_, y52 := bits.Mul64(x52, orderK0)
	x59, x58 = bits.Mul64(y52, 0xfffffffeffffffff)
	var x60 uint64
	var x61 uint64
	x61, x60 = bits.Mul64(y52, 0xffffffffffffffff)
	var x62 uint64
	var x63 uint64
	x63, x62 = bits.Mul64(y52, 0x7203df6b21c6052b)
	var x64 uint64
	var x65 uint64
	x65, x64 = bits.Mul64(y52, 0x53bbf40939d54123)
	var x66 uint64
	var x67 uint64
	x66, x67 = bits.Add64(x65, x62, uint64(0x0))
	var x68 uint64
	var x69 uint64
	x68, x69 = bits.Add64(x63, x60, uint64(sm2p256Uint1(x67)))
	var x70 uint64
	var x71 uint64
	x70, x71 = bits.Add64(x61, x58, uint64(sm2p256Uint1(x69)))
	var x73 uint64
	_, x73 = bits.Add64(x52, x64, uint64(0x0))
	var x74 uint64
	var x75 uint64
	x74, x75 = bits.Add64(x54, x66, uint64(sm2p256Uint1(x73)))
	var x76 uint64
	var x77 uint64
	x76, x77 = bits.Add64(x56, x68, uint64(sm2p256Uint1(x75)))
	var x78 uint64
	var x79 uint64
	x78, x79 = bits.Add64((uint64(sm2p256Uint1(x57)) + (uint64(sm2p256Uint1(x51)) + (uint64(sm2p256Uint1(x43)) + x31))), x70, uint64(sm2p256Uint1(x77)))
	var x80 uint64
	var x81 uint64
	x80, x81 = bits.Add64(x74, arg1[3], uint64(0x0))
	var x82 uint64
	var x83 uint64
	x82, x83 = bits.Add64(x76, uint64(0x0), uint64(sm2p256Uint1(x81)))
	var x84 uint64
	var x85 uint64
	x84, x85 = bits.Add64(x78, uint64(0x0), uint64(sm2p256Uint1(x83)))
	var x86 uint64
	var x87 uint64
	_, y80 := bits.Mul64(x80, orderK0)
	x87, x86 = bits.Mul64(y80, 0xfffffffeffffffff)
	var x88 uint64
	var x89 uint64
	x89, x88 = bits.Mul64(y80, 0xffffffffffffffff)
	var x90 uint64
	var x91 uint64
	x91, x90 = bits.Mul64(y80, 0x7203df6b21c6052b)
	var x92 uint64
	var x93 uint64
	x93, x92 = bits.Mul64(y80, 0x53bbf40939d54123)
	var x94 uint64
	var x95 uint64
	x94, x95 = bits.Add64(x93, x90, uint64(0x0))
	var x96 uint64
	var x97 uint64
	x96, x97 = bits.Add64(x91, x88, uint64(sm2p256Uint1(x95)))
	var x98 uint64
	var x99 uint64
	x98, x99 = bits.Add64(x89, x86, uint64(sm2p256Uint1(x97)))
	var x101 uint64
	_, x101 = bits.Add64(x80, x92, uint64(0x0))
	var x102 uint64
	var x103 uint64
	x102, x103 = bits.Add64(x82, x94, uint64(sm2p256Uint1(x101)))
	var x104 uint64
	var x105 uint64
	x104, x105 = bits.Add64(x84, x96, uint64(sm2p256Uint1(x103)))
	var x106 uint64
	var x107 uint64
	x106, x107 = bits.Add64((uint64(sm2p256Uint1(x85)) + (uint64(sm2p256Uint1(x79)) + (uint64(sm2p256Uint1(x71)) + x59))), x98, uint64(sm2p256Uint1(x105)))
	x108 := (uint64(sm2p256Uint1(x107)) + (uint64(sm2p256Uint1(x99)) + x87))
	var x109 uint64
	var x110 uint64
	x109, x110 = bits.Sub64(x102, 0x53bbf40939d54123, uint64(0x0))
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Sub64(x104, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x110)))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Sub64(x106, 0xffffffffffffffff, uint64(sm2p256Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Sub64(x108, 0xfffffffeffffffff, uint64(sm2p256Uint1(x114)))
	var x118 uint64
	_, x118 = bits.Sub64(uint64(0x0), uint64(0x0), uint64(sm2p256Uint1(x116)))
	var x119 uint64
	sm2p256CmovznzU64(&x119, sm2p256Uint1(x118), x109, x102)
	var x120 uint64
	sm2p256CmovznzU64(&x120, sm2p256Uint1(x118), x111, x104)
	var x121 uint64
	sm2p256CmovznzU64(&x121, sm2p256Uint1(x118), x113, x106)
	var x122 uint64
	sm2p256CmovznzU64(&x122, sm2p256Uint1(x118), x115, x108)
	out1[0] = x119
	out1[1] = x120
	out1[2] = x121
	out1[3] = x122
}

// sm2p256OrderToMontgomery translates a field element into the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
// Postconditions:
//   eval (from_montgomery out1) mod m = eval arg1 mod m
//   0 ≤ eval out1 < m
//
func sm2p256OrderToMontgomery(out1 *sm2p256MontgomeryDomainFieldElement, arg1 *sm2p256NonMontgomeryDomainFieldElement) {
	x1 := arg1[1]
	x2 := arg1[2]
	x3 := arg1[3]
	x4 := arg1[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, 0x1eb5e412a22b3d3b)
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, 0x620fc84c3affe0d4)
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, 0x3464504ade6fa2fa)
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, 0x901192af7c114f20)
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Add64(x12, x9, uint64(0x0))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x10, x7, uint64(sm2p256Uint1(x14)))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x8, x5, uint64(sm2p256Uint1(x16)))
	var x19 uint64
	var x20 uint64
	_, y11 := bits.Mul64(x11, orderK0)
	x20, x19 = bits.Mul64(y11, 0xfffffffeffffffff)
	var x21 uint64
	var x22 uint64
	x22, x21 = bits.Mul64(y11, 0xffffffffffffffff)
	var x23 uint64
	var x24 uint64
	x24, x23 = bits.Mul64(y11, 0x7203df6b21c6052b)
	var x25 uint64
	var x26 uint64
	x26, x25 = bits.Mul64(y11, 0x53bbf40939d54123)
	var x27 uint64
	var x28 uint64
	x27, x28 = bits.Add64(x26, x23, uint64(0x0))
	var x29 uint64
	var x30 uint64
	x29, x30 = bits.Add64(x24, x21, uint64(sm2p256Uint1(x28)))
	var x31 uint64
	var x32 uint64
	x31, x32 = bits.Add64(x22, x19, uint64(sm2p256Uint1(x30)))
	var x34 uint64
	_, x34 = bits.Add64(x11, x25, uint64(0x0))
	var x35 uint64
	var x36 uint64
	x35, x36 = bits.Add64(x13, x27, uint64(sm2p256Uint1(x34)))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x15, x29, uint64(sm2p256Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x17, x31, uint64(sm2p256Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64((uint64(sm2p256Uint1(x18)) + x6), (uint64(sm2p256Uint1(x32)) + x20), uint64(sm2p256Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x44, x43 = bits.Mul64(x1, 0x1eb5e412a22b3d3b)
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(x1, 0x620fc84c3affe0d4)
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, 0x3464504ade6fa2fa)
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, 0x901192af7c114f20)
	var x51 uint64
	var x52 uint64
	x51, x52 = bits.Add64(x50, x47, uint64(0x0))
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x48, x45, uint64(sm2p256Uint1(x52)))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x46, x43, uint64(sm2p256Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(x35, x49, uint64(0x0))
	var x59 uint64
	var x60 uint64
	x59, x60 = bits.Add64(x37, x51, uint64(sm2p256Uint1(x58)))
	var x61 uint64
	var x62 uint64
	x61, x62 = bits.Add64(x39, x53, uint64(sm2p256Uint1(x60)))
	var x63 uint64
	var x64 uint64
	x63, x64 = bits.Add64(x41, x55, uint64(sm2p256Uint1(x62)))
	var x65 uint64
	var x66 uint64
	_, y57 := bits.Mul64(x57, orderK0)
	x66, x65 = bits.Mul64(y57, 0xfffffffeffffffff)
	var x67 uint64
	var x68 uint64
	x68, x67 = bits.Mul64(y57, 0xffffffffffffffff)
	var x69 uint64
	var x70 uint64
	x70, x69 = bits.Mul64(y57, 0x7203df6b21c6052b)
	var x71 uint64
	var x72 uint64
	x72, x71 = bits.Mul64(y57, 0x53bbf40939d54123)
	var x73 uint64
	var x74 uint64
	x73, x74 = bits.Add64(x72, x69, uint64(0x0))
	var x75 uint64
	var x76 uint64
	x75, x76 = bits.Add64(x70, x67, uint64(sm2p256Uint1(x74)))
	var x77 uint64
	var x78 uint64
	x77, x78 = bits.Add64(x68, x65, uint64(sm2p256Uint1(x76)))
	var x80 uint64
	_, x80 = bits.Add64(x57, x71, uint64(0x0))
	var x81 uint64
	var x82 uint64
	x81, x82 = bits.Add64(x59, x73, uint64(sm2p256Uint1(x80)))
	var x83 uint64
	var x84 uint64
	x83, x84 = bits.Add64(x61, x75, uint64(sm2p256Uint1(x82)))
	var x85 uint64
	var x86 uint64
	x85, x86 = bits.Add64(x63, x77, uint64(sm2p256Uint1(x84)))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(((uint64(sm2p256Uint1(x64)) + uint64(sm2p256Uint1(x42))) + (uint64(sm2p256Uint1(x56)) + x44)), (uint64(sm2p256Uint1(x78)) + x66), uint64(sm2p256Uint1(x86)))
	var x89 uint64
	var x90 uint64
	x90, x89 = bits.Mul64(x2, 0x1eb5e412a22b3d3b)
	var x91 uint64
	var x92 uint64
	x92, x91 = bits.Mul64(x2, 0x620fc84c3affe0d4)
	var x93 uint64
	var x94 uint64
	x94, x93 = bits.Mul64(x2, 0x3464504ade6fa2fa)
	var x95 uint64
	var x96 uint64
	x96, x95 = bits.Mul64(x2, 0x901192af7c114f20)
	var x97 uint64
	var x98 uint64
	x97, x98 = bits.Add64(x96, x93, uint64(0x0))
	var x99 uint64
	var x100 uint64
	x99, x100 = bits.Add64(x94, x91, uint64(sm2p256Uint1(x98)))
	var x101 uint64
	var x102 uint64
	x101, x102 = bits.Add64(x92, x89, uint64(sm2p256Uint1(x100)))
	var x103 uint64
	var x104 uint64
	x103, x104 = bits.Add64(x81, x95, uint64(0x0))
	var x105 uint64
	var x106 uint64
	x105, x106 = bits.Add64(x83, x97, uint64(sm2p256Uint1(x104)))
	var x107 uint64
	var x108 uint64
	x107, x108 = bits.Add64(x85, x99, uint64(sm2p256Uint1(x106)))
	var x109 uint64
	var x110 uint64
	x109, x110 = bits.Add64(x87, x101, uint64(sm2p256Uint1(x108)))
	var x111 uint64
	var x112 uint64
	_, y103 := bits.Mul64(x103, orderK0)
	x112, x111 = bits.Mul64(y103, 0xfffffffeffffffff)
	var x113 uint64
	var x114 uint64
	x114, x113 = bits.Mul64(y103, 0xffffffffffffffff)
	var x115 uint64
	var x116 uint64
	x116, x115 = bits.Mul64(y103, 0x7203df6b21c6052b)
	var x117 uint64
	var x118 uint64
	x118, x117 = bits.Mul64(y103, 0x53bbf40939d54123)
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x118, x115, uint64(0x0))
	var x121 uint64
	var x122 uint64
	x121, x122 = bits.Add64(x116, x113, uint64(sm2p256Uint1(x120)))
	var x123 uint64
	var x124 uint64
	x123, x124 = bits.Add64(x114, x111, uint64(sm2p256Uint1(x122)))
	var x126 uint64
	_, x126 = bits.Add64(x103, x117, uint64(0x0))
	var x127 uint64
	var x128 uint64
	x127, x128 = bits.Add64(x105, x119, uint64(sm2p256Uint1(x126)))
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x107, x121, uint64(sm2p256Uint1(x128)))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x109, x123, uint64(sm2p256Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(((uint64(sm2p256Uint1(x110)) + uint64(sm2p256Uint1(x88))) + (uint64(sm2p256Uint1(x102)) + x90)), (uint64(sm2p256Uint1(x124)) + x112), uint64(sm2p256Uint1(x132)))
	var x135 uint64
	var x136 uint64
	x136, x135 = bits.Mul64(x3, 0x1eb5e412a22b3d3b)
	var x137 uint64
	var x138 uint64
	x138, x137 = bits.Mul64(x3, 0x620fc84c3affe0d4)
	var x139 uint64
	var x140 uint64
	x140, x139 = bits.Mul64(x3, 0x3464504ade6fa2fa)
	var x141 uint64
	var x142 uint64
	x142, x141 = bits.Mul64(x3, 0x901192af7c114f20)
	var x143 uint64
	var x144 uint64
	x143, x144 = bits.Add64(x142, x139, uint64(0x0))
	var x145 uint64
	var x146 uint64
	x145, x146 = bits.Add64(x140, x137, uint64(sm2p256Uint1(x144)))
	var x147 uint64
	var x148 uint64
	x147, x148 = bits.Add64(x138, x135, uint64(sm2p256Uint1(x146)))
	var x149 uint64
	var x150 uint64
	x149, x150 = bits.Add64(x127, x141, uint64(0x0))
	var x151 uint64
	var x152 uint64
	x151, x152 = bits.Add64(x129, x143, uint64(sm2p256Uint1(x150)))
	var x153 uint64
	var x154 uint64
	x153, x154 = bits.Add64(x131, x145, uint64(sm2p256Uint1(x152)))
	var x155 uint64
	var x156 uint64
	x155, x156 = bits.Add64(x133, x147, uint64(sm2p256Uint1(x154)))
	var x157 uint64
	var x158 uint64
	_, y149 := bits.Mul64(x149, orderK0)
	x158, x157 = bits.Mul64(y149, 0xfffffffeffffffff)
	var x159 uint64
	var x160 uint64
	x160, x159 = bits.Mul64(y149, 0xffffffffffffffff)
	var x161 uint64
	var x162 uint64
	x162, x161 = bits.Mul64(y149, 0x7203df6b21c6052b)
	var x163 uint64
	var x164 uint64
	x164, x163 = bits.Mul64(y149, 0x53bbf40939d54123)
	var x165 uint64
	var x166 uint64
	x165, x166 = bits.Add64(x164, x161, uint64(0x0))
	var x167 uint64
	var x168 uint64
	x167, x168 = bits.Add64(x162, x159, uint64(sm2p256Uint1(x166)))
	var x169 uint64
	var x170 uint64
	x169, x170 = bits.Add64(x160, x157, uint64(sm2p256Uint1(x168)))
	var x172 uint64
	_, x172 = bits.Add64(x149, x163, uint64(0x0))
	var x173 uint64
	var x174 uint64
	x173, x174 = bits.Add64(x151, x165, uint64(sm2p256Uint1(x172)))
	var x175 uint64
	var x176 uint64
	x175, x176 = bits.Add64(x153, x167, uint64(sm2p256Uint1(x174)))
	var x177 uint64
	var x178 uint64
	x177, x178 = bits.Add64(x155, x169, uint64(sm2p256Uint1(x176)))
	var x179 uint64
	var x180 uint64
	x179, x180 = bits.Add64(((uint64(sm2p256Uint1(x156)) + uint64(sm2p256Uint1(x134))) + (uint64(sm2p256Uint1(x148)) + x136)), (uint64(sm2p256Uint1(x170)) + x158), uint64(sm2p256Uint1(x178)))
	var x181 uint64
	var x182 uint64
	x181, x182 = bits.Sub64(x173, 0x53bbf40939d54123, uint64(0x0))
	var x183 uint64
	var x184 uint64
	x183, x184 = bits.Sub64(x175, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x182)))
	var x185 uint64
	var x186 uint64
	x185, x186 = bits.Sub64(x177, 0xffffffffffffffff, uint64(sm2p256Uint1(x184)))
	var x187 uint64
	var x188 uint64
	x187, x188 = bits.Sub64(x179, 0xfffffffeffffffff, uint64(sm2p256Uint1(x186)))
	var x190 uint64
	_, x190 = bits.Sub64(uint64(sm2p256Uint1(x180)), uint64(0x0), uint64(sm2p256Uint1(x188)))
	var x191 uint64
	sm2p256CmovznzU64(&x191, sm2p256Uint1(x190), x181, x173)
	var x192 uint64
	sm2p256CmovznzU64(&x192, sm2p256Uint1(x190), x183, x175)
	var x193 uint64
	sm2p256CmovznzU64(&x193, sm2p256Uint1(x190), x185, x177)
	var x194 uint64
	sm2p256CmovznzU64(&x194, sm2p256Uint1(x190), x187, x179)
	out1[0] = x191
	out1[1] = x192
	out1[2] = x193
	out1[3] = x194
}
