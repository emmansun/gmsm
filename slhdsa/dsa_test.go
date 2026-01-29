// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package slhdsa

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type slhtest struct {
	ParameterSet         string `json:"parameterSet"`
	Sk                   string `json:"sk"`
	Pk                   string `json:"pk"`
	AdditionalRandomness string `json:"additionalRandomness,omitempty"`
	Message              string `json:"message"`
	Context              string `json:"context,omitempty"`
	Signature            string `json:"signature"`
}

func loadData(filename string) (*slhtest, error) {
	file := filepath.Join("testdata", filename)
	// read json conentent from file and Unmarshal to slhtest
	in, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	var data slhtest
	if err := json.NewDecoder(in).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}

func TestSignFromFiles(t *testing.T) {
	// list files in testdata
	files, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := loadData(file.Name())
		if err != nil {
			t.Fatalf("loadData failed: %v", err)
		}
		testData(t, file.Name(), data)
	}
}

func testData(t *testing.T, filename string, tc *slhtest) {
	t.Helper()
	params, ok := GetParameterSet(tc.ParameterSet)
	if !ok {
		t.Fatalf("%v GetParameterSet(%s)", filename, tc.ParameterSet)
	}
	skBytes, _ := hex.DecodeString(tc.Sk)
	pkBytes, _ := hex.DecodeString(tc.Pk)
	addRand, _ := hex.DecodeString(tc.AdditionalRandomness)
	message, _ := hex.DecodeString(tc.Message)
	context, _ := hex.DecodeString(tc.Context)
	sig, _ := hex.DecodeString(tc.Signature)
	sigOriginal := sig
	privKey, err := params.NewPrivateKey(skBytes)
	if err != nil {
		t.Fatalf("%v NewPrivateKey(%x) = %v", filename, skBytes, err)
	}
	sig2, err := privKey.Sign(nil, message, &Options{context, addRand})
	if err != nil {
		t.Fatalf("%v Sign(%x,%x) = %v", filename, message, context, err)
	}
	// check R
	if !bytes.Equal(sig[:params.n], sig2[:params.n]) {
		t.Errorf("signature.R = %x, want %x", sig2[:params.n], sig[:params.n])
	}
	// check SIGfors
	sig2 = sig2[params.n:]
	sig = sig[params.n:]
	if !bytes.Equal(sig[:privKey.params.n*(privKey.params.a+1)*privKey.params.k], sig2[:privKey.params.n*(privKey.params.a+1)*privKey.params.k]) {
		t.Errorf("signature.SIGfors = %x, want %x", sig2[:privKey.params.n*(privKey.params.a+1)*privKey.params.k], sig[:privKey.params.n*(privKey.params.a+1)*privKey.params.k])
	}
	// check SIGht
	sig2 = sig2[privKey.params.n*(privKey.params.a+1)*privKey.params.k:]
	sig = sig[privKey.params.n*(privKey.params.a+1)*privKey.params.k:]
	for i := range int(privKey.params.d) {
		if !bytes.Equal(sig[:privKey.params.n*(privKey.params.len+privKey.params.hm)], sig2[:privKey.params.n*(privKey.params.len+privKey.params.hm)]) {
			t.Errorf("signature.SIGht = %v %x, want %x", i, sig2[:privKey.params.n*(privKey.params.len+privKey.params.hm)], sig[:privKey.params.n*(privKey.params.len+privKey.params.hm)])
		}
		sig2 = sig2[privKey.params.n*(privKey.params.len+privKey.params.hm):]
		sig = sig[privKey.params.n*(privKey.params.len+privKey.params.hm):]
	}
	// test verify
	pub, err := params.NewPublicKey(pkBytes)
	if err != nil {
		t.Fatalf("%v NewPublicKey(%x) = %v", filename, pkBytes, err)
	}
	if !pub.VerifyWithOptions(sigOriginal, message, &Options{Context: context}) {
		t.Errorf("%v Verify() = false, want true", filename)
	}
}
