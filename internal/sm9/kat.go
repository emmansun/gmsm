// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm9

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/internal/bigmod"
	"github.com/emmansun/gmsm/internal/sm3"
	"github.com/emmansun/gmsm/internal/sm9/bn256"
)

// KATSignSample verifies SM9 sign primitives using GB/T 32918 Appendix A vectors.
// It tests hashH2, ScalarBaseMult, ScalarMult and user key generation.
func KATSignSample() error {
	expectedH, _ := hex.DecodeString("823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb")
	expectedHNat, err := bigmod.NewNat().SetBytes(expectedH, orderNat)
	if err != nil {
		return errors.New("sign: failed to parse expected h: " + err.Error())
	}
	expectedS := "0473bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05"
	hash := []byte("Chinese IBS standard")
	hid := byte(0x01)
	uid := []byte("Alice")
	r, _ := hex.DecodeString("033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe")
	rNat, err := bigmod.NewNat().SetBytes(r, orderNat)
	if err != nil {
		return errors.New("sign: failed to parse r: " + err.Error())
	}
	kb, _ := hex.DecodeString("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	masterKey, err := NewSignMasterPrivateKey(kb)
	if err != nil {
		return errors.New("sign: failed to create master key: " + err.Error())
	}

	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		return errors.New("sign: failed to generate user key: " + err.Error())
	}

	// Test ScalarBaseMult with standard r.
	w, err := userKey.SignMasterPublicKey.ScalarBaseMult(bn256.NormalizeScalar(r))
	if err != nil {
		return errors.New("sign: ScalarBaseMult failed: " + err.Error())
	}

	// Test hashH2.
	var buffer []byte
	buffer = append(buffer, hash...)
	buffer = append(buffer, w.Marshal()...)
	h := hashH2(buffer)
	if h.Equal(expectedHNat) == 0 {
		return errors.New("sign: hashH2 mismatch")
	}

	// Test signature S component.
	rNat.Sub(h, orderNat)
	s, err := new(bn256.G1).ScalarMult(userKey.PrivateKey, rNat.Bytes(orderNat))
	if err != nil {
		return errors.New("sign: ScalarMult failed: " + err.Error())
	}
	if hex.EncodeToString(s.MarshalUncompressed()) != expectedS {
		return errors.New("sign: signature S mismatch")
	}

	return nil
}

// KATKeyExchangeSample verifies SM9 key exchange using GB/T 32918 Appendix B vectors.
func KATKeyExchangeSample() error {
	hid := byte(0x02)
	expectedKey := "c5c13a8f59a97cdeae64f16a2272a9e7"
	expectedSigB := "3bb4bcee8139c960b4d6566db1e0d5f0b2767680e5e1bf934103e6c66e40ffee"
	expectedSigA := "195d1b7256ba7e0e67c71202a25f8c94ff8241702c2f55d613ae1c6b98215172"

	kb, _ := hex.DecodeString("0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F")
	masterKey, err := NewEncryptMasterPrivateKey(kb)
	if err != nil {
		return errors.New("keyex: failed to create master key: " + err.Error())
	}

	userA := []byte("Alice")
	userB := []byte("Bob")

	userKeyA, err := masterKey.GenerateUserKey(userA, hid)
	if err != nil {
		return errors.New("keyex: failed to generate user A key: " + err.Error())
	}
	initiator := userKeyA.NewKeyExchange(userA, userB, 16, true)

	userKeyB, err := masterKey.GenerateUserKey(userB, hid)
	if err != nil {
		return errors.New("keyex: failed to generate user B key: " + err.Error())
	}
	responder := userKeyB.NewKeyExchange(userB, userA, 16, true)
	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()

	// A1-A4 with fixed random.
	rA, _ := hex.DecodeString("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8")
	k, err := bigmod.NewNat().SetBytes(rA, orderNat)
	if err != nil {
		return errors.New("keyex: failed to parse rA: " + err.Error())
	}
	initKeyExchange(initiator, hid, k)

	expectedSecret := "047cba5b19069ee66aa79d490413d11846b9ba76dd22567f809cf23b6d964bb265a9760c99cb6f706343fed05637085864958d6c90902aba7d405fbedf7b781599"
	if hex.EncodeToString(initiator.secret) != expectedSecret {
		return errors.New("keyex: initiator secret mismatch")
	}

	// B1-B7 with fixed random.
	rB, _ := hex.DecodeString("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE")
	k, err = bigmod.NewNat().SetBytes(rB, orderNat)
	if err != nil {
		return errors.New("keyex: failed to parse rB: " + err.Error())
	}
	rBData, sigB, err := respondKeyExchange(responder, hid, k, initiator.secret)
	if err != nil {
		return errors.New("keyex: respond failed: " + err.Error())
	}
	if hex.EncodeToString(sigB) != expectedSigB {
		return errors.New("keyex: signature B mismatch")
	}

	// A5-A8.
	key1, sigA, err := initiator.ConfirmResponder(rBData, sigB)
	if err != nil {
		return errors.New("keyex: confirm responder failed: " + err.Error())
	}
	if hex.EncodeToString(key1) != expectedKey {
		return errors.New("keyex: key A mismatch")
	}
	if hex.EncodeToString(sigA) != expectedSigA {
		return errors.New("keyex: signature A mismatch")
	}

	// B8.
	key2, err := responder.ConfirmInitiator(sigA)
	if err != nil {
		return errors.New("keyex: confirm initiator failed: " + err.Error())
	}
	if hex.EncodeToString(key2) != expectedKey {
		return errors.New("keyex: key B mismatch")
	}

	return nil
}

// KATWrapKeySample verifies SM9 key wrapping using GB/T 32918 Appendix C vectors.
// It tests master key generation, user key generation, ScalarMult, pairing, and KDF.
func KATWrapKeySample() error {
	expectedMasterPub := "787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1"
	expectedUserPriv := "94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1"
	expectedUserPub := "709d165808b0a43e2574e203fa885abcbab16a240c4c1916552e7c43d09763b8693269a6be2456f43333758274786b6051ff87b7f198da4ba1a2c6e336f51fcc"
	expectedCipher := "1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c"
	expectedKey := "4ff5cf86d2ad40c8f4bac98d76abdbde0c0e2f0a829d3f911ef5b2bce0695480"

	kb, _ := hex.DecodeString("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22")
	masterKey, err := NewEncryptMasterPrivateKey(kb)
	if err != nil {
		return errors.New("wrap: failed to create master key: " + err.Error())
	}
	if hex.EncodeToString(masterKey.MasterPublicKey.Marshal()) != expectedMasterPub {
		return errors.New("wrap: master public key mismatch")
	}

	uid := []byte("Bob")
	hid := byte(0x03)

	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		return errors.New("wrap: failed to generate user key: " + err.Error())
	}
	if hex.EncodeToString(userKey.PrivateKey.Marshal()) != expectedUserPriv {
		return errors.New("wrap: user private key mismatch")
	}

	q := masterKey.PublicKey().GenerateUserPublicKey(uid, hid)
	if hex.EncodeToString(q.Marshal()) != expectedUserPub {
		return errors.New("wrap: user public key mismatch")
	}

	// Test ScalarMult with standard r.
	rb, _ := hex.DecodeString("74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722")
	r := new(big.Int).SetBytes(rb)
	cipher, err := new(bn256.G1).ScalarMult(q, bn256.NormalizeScalar(r.Bytes()))
	if err != nil {
		return errors.New("wrap: ScalarMult failed: " + err.Error())
	}
	if hex.EncodeToString(cipher.Marshal()) != expectedCipher {
		return errors.New("wrap: cipher mismatch")
	}

	// Test pairing and KDF.
	g := bn256.Pair(masterKey.PublicKey().MasterPublicKey, bn256.Gen2)
	w := new(bn256.GT).ScalarMult(g, r)
	var buffer []byte
	buffer = append(buffer, cipher.Marshal()...)
	buffer = append(buffer, w.Marshal()...)
	buffer = append(buffer, uid...)
	key := sm3.Kdf(buffer, 32)
	if hex.EncodeToString(key) != expectedKey {
		return errors.New("wrap: derived key mismatch")
	}

	// Test UnwrapKey.
	key2, err := userKey.UnwrapKey(uid, cipher.MarshalUncompressed(), 32)
	if err != nil {
		return errors.New("wrap: UnwrapKey failed: " + err.Error())
	}
	if hex.EncodeToString(key2) != expectedKey {
		return errors.New("wrap: unwrapped key mismatch")
	}

	return nil
}

// KATEncryptSample verifies SM9 encryption using GB/T 32918 Appendix D vectors.
func KATEncryptSample() error {
	plaintext := []byte("Chinese IBE standard")
	expectedCipher := "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0"
	expectedKey := "58373260f067ec48667c21c144f8bc33cd3049788651ffd5f738003e51df31174d0e4e402fd87f4581b612f74259db574f67ece6"
	expectedCiphertext := "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f3671b5f5b0e951489682f3e64e1378cdd5da9513b1c"

	kb, _ := hex.DecodeString("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22")
	masterKey, err := NewEncryptMasterPrivateKey(kb)
	if err != nil {
		return errors.New("encrypt: failed to create master key: " + err.Error())
	}

	uid := []byte("Bob")
	hid := byte(0x03)

	q := masterKey.PublicKey().GenerateUserPublicKey(uid, hid)

	rb, _ := hex.DecodeString("AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C")
	r := new(big.Int).SetBytes(rb)
	cipher, err := new(bn256.G1).ScalarMult(q, bn256.NormalizeScalar(r.Bytes()))
	if err != nil {
		return errors.New("encrypt: ScalarMult failed: " + err.Error())
	}
	if hex.EncodeToString(cipher.Marshal()) != expectedCipher {
		return errors.New("encrypt: cipher mismatch")
	}

	g := bn256.Pair(masterKey.PublicKey().MasterPublicKey, bn256.Gen2)
	w := new(bn256.GT).ScalarMult(g, r)

	var buffer []byte
	buffer = append(buffer, cipher.Marshal()...)
	buffer = append(buffer, w.Marshal()...)
	buffer = append(buffer, uid...)

	key := sm3.Kdf(buffer, len(plaintext)+32)
	if hex.EncodeToString(key) != expectedKey {
		return errors.New("encrypt: derived key mismatch")
	}

	// XOR plaintext into key buffer.
	subtle.XORBytes(key, key[:len(plaintext)], plaintext)

	// Compute C3 = H(key || ...).
	hash := sm3.New()
	hash.Write(key)
	c3 := hash.Sum(nil)

	ciphertext := append(cipher.Marshal(), c3...)
	ciphertext = append(ciphertext, key[:len(plaintext)]...)
	if hex.EncodeToString(ciphertext) != expectedCiphertext {
		return errors.New("encrypt: ciphertext mismatch")
	}

	return nil
}
