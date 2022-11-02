package smx509

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

func TestParsePKCS1PrivateKey(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	priv, err := ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(rsaPrivateKey.PublicKey.N) != 0 ||
		priv.PublicKey.E != rsaPrivateKey.PublicKey.E ||
		priv.D.Cmp(rsaPrivateKey.D) != 0 ||
		priv.Primes[0].Cmp(rsaPrivateKey.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(rsaPrivateKey.Primes[1]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, rsaPrivateKey)
	}

	// This private key includes an invalid prime that
	// rsa.PrivateKey.Validate should reject.
	data := []byte("0\x16\x02\x00\x02\x02\u007f\x00\x02\x0200\x02\x0200\x02\x02\x00\x01\x02\x02\u007f\x00")
	if _, err := ParsePKCS1PrivateKey(data); err == nil {
		t.Errorf("parsing invalid private key did not result in an error")
	}
}

func TestMarshalRSAPrivateKey(t *testing.T) {
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
			E: 3,
		},
		D: fromBase10("10897585948254795600358846499957366070880176878341177571733155050184921896034527397712889205732614568234385175145686545381899460748279607074689061600935843283397424506622998458510302603922766336783617368686090042765718290914099334449154829375179958369993407724946186243249568928237086215759259909861748642124071874879861299389874230489928271621259294894142840428407196932444474088857746123104978617098858619445675532587787023228852383149557470077802718705420275739737958953794088728369933811184572620857678792001136676902250566845618813972833750098806496641114644760255910789397593428910198080271317419213080834885003"),
		Primes: []*big.Int{
			fromBase10("1025363189502892836833747188838978207017355117492483312747347695538428729137306368764177201532277413433182799108299960196606011786562992097313508180436744488171474690412562218914213688661311117337381958560443"),
			fromBase10("3467903426626310123395340254094941045497208049900750380025518552334536945536837294961497712862519984786362199788654739924501424784631315081391467293694361474867825728031147665777546570788493758372218019373"),
			fromBase10("4597024781409332673052708605078359346966325141767460991205742124888960305710298765592730135879076084498363772408626791576005136245060321874472727132746643162385746062759369754202494417496879741537284589047"),
		},
	}

	derBytes := MarshalPKCS1PrivateKey(priv)

	priv2, err := ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		t.Errorf("error parsing serialized key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(priv2.PublicKey.N) != 0 ||
		priv.PublicKey.E != priv2.PublicKey.E ||
		priv.D.Cmp(priv2.D) != 0 ||
		len(priv2.Primes) != 3 ||
		priv.Primes[0].Cmp(priv2.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(priv2.Primes[1]) != 0 ||
		priv.Primes[2].Cmp(priv2.Primes[2]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, priv2)
	}
}

func TestMarshalRSAPublicKey(t *testing.T) {
	pub := &rsa.PublicKey{
		N: fromBase10("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
		E: 3,
	}
	derBytes := MarshalPKCS1PublicKey(pub)
	pub2, err := ParsePKCS1PublicKey(derBytes)
	if err != nil {
		t.Errorf("ParsePKCS1PublicKey: %s", err)
	}
	if pub.N.Cmp(pub2.N) != 0 || pub.E != pub2.E {
		t.Errorf("ParsePKCS1PublicKey = %+v, want %+v", pub, pub2)
	}

	// It's never been documented that asn1.Marshal/Unmarshal on rsa.PublicKey works,
	// but it does, and we know of code that depends on it.
	// Lock that in, even though we'd prefer that people use MarshalPKCS1PublicKey and ParsePKCS1PublicKey.
	derBytes2, err := asn1.Marshal(*pub)
	if err != nil {
		t.Errorf("Marshal(rsa.PublicKey): %v", err)
	} else if !bytes.Equal(derBytes, derBytes2) {
		t.Errorf("Marshal(rsa.PublicKey) = %x, want %x", derBytes2, derBytes)
	}
	pub3 := new(rsa.PublicKey)
	rest, err := asn1.Unmarshal(derBytes, pub3)
	if err != nil {
		t.Errorf("Unmarshal(rsa.PublicKey): %v", err)
	}
	if len(rest) != 0 || pub.N.Cmp(pub3.N) != 0 || pub.E != pub3.E {
		t.Errorf("Unmarshal(rsa.PublicKey) = %+v, %q want %+v, %q", pub, rest, pub2, []byte(nil))
	}

	publicKeys := []struct {
		derBytes          []byte
		expectedErrSubstr string
	}{
		{
			derBytes: []byte{
				0x30, 6, // SEQUENCE, 6 bytes
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				3, // 3
			},
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				0xff,    // -1
				0x02, 1, // INTEGER, 1 byte
				3,
			},
			expectedErrSubstr: "zero or negative",
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				0xff, // -1
			},
			expectedErrSubstr: "zero or negative",
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				3,
				1,
			},
			expectedErrSubstr: "trailing data",
		}, {
			derBytes: []byte{
				0x30, 9, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 4, // INTEGER, 4 bytes
				0x7f, 0xff, 0xff, 0xff,
			},
		}, {
			derBytes: []byte{
				0x30, 10, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 5, // INTEGER, 5 bytes
				0x00, 0x80, 0x00, 0x00, 0x00,
			},
			// On 64-bit systems, encoding/asn1 will accept the
			// public exponent, but ParsePKCS1PublicKey will return
			// an error. On 32-bit systems, encoding/asn1 will
			// return the error. The common substring of both error
			// is the word “large”.
			expectedErrSubstr: "large",
		},
	}

	for i, test := range publicKeys {
		shouldFail := len(test.expectedErrSubstr) > 0
		pub, err := ParsePKCS1PublicKey(test.derBytes)
		if shouldFail {
			if err == nil {
				t.Errorf("#%d: unexpected success, got %#v", i, pub)
			} else if !strings.Contains(err.Error(), test.expectedErrSubstr) {
				t.Errorf("#%d: expected error containing %q, got %s", i, test.expectedErrSubstr, err)
			}
		} else {
			if err != nil {
				t.Errorf("#%d: unexpected failure: %s", i, err)
				continue
			}
			reserialized := MarshalPKCS1PublicKey(pub)
			if !bytes.Equal(reserialized, test.derBytes) {
				t.Errorf("#%d: failed to reserialize: got %x, expected %x", i, reserialized, test.derBytes)
			}
		}
	}
}

const hexPKCS1TestPKCS8Key = "30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ffa97b4f99df4ff122b70e59ac9b992f3bc2b3dde17d53c1a34928719b02e8fd17839499bfbd515bd6ef99c7a1c47a239718fe36bfd824c0d96060084b5f67f0273443007a24dfaf5634f7772c9346e10eb294c2306671a5a5e719ae24b4de467291bc571014b0e02dec04534d66a9bb171d644b66b091780e8d020301000102818100b595778383c4afdbab95d2bfed12b3f93bb0a73a7ad952f44d7185fd9ec6c34de8f03a48770f2009c8580bcd275e9632714e9a5e3f32f29dc55474b2329ff0ebc08b3ffcb35bc96e6516b483df80a4a59cceb71918cbabf91564e64a39d7e35dce21cb3031824fdbc845dba6458852ec16af5dddf51a8397a8797ae0337b1439024100ea0eb1b914158c70db39031dd8904d6f18f408c85fbbc592d7d20dee7986969efbda081fdf8bc40e1b1336d6b638110c836bfdc3f314560d2e49cd4fbde1e20b024100e32a4e793b574c9c4a94c8803db5152141e72d03de64e54ef2c8ed104988ca780cd11397bc359630d01b97ebd87067c5451ba777cf045ca23f5912f1031308c702406dfcdbbd5a57c9f85abc4edf9e9e29153507b07ce0a7ef6f52e60dcfebe1b8341babd8b789a837485da6c8d55b29bbb142ace3c24a1f5b54b454d01b51e2ad03024100bd6a2b60dee01e1b3bfcef6a2f09ed027c273cdbbaf6ba55a80f6dcc64e4509ee560f84b4f3e076bd03b11e42fe71a3fdd2dffe7e0902c8584f8cad877cdc945024100aa512fa4ada69881f1d8bb8ad6614f192b83200aef5edf4811313d5ef30a86cbd0a90f7b025c71ea06ec6b34db6306c86b1040670fd8654ad7291d066d06d031"
const hexPKCS1TestECKey = "3081a40201010430bdb9839c08ee793d1157886a7a758a3c8b2a17a4df48f17ace57c72c56b4723cf21dcda21d4e1ad57ff034f19fcfd98ea00706052b81040022a16403620004feea808b5ee2429cfcce13c32160e1c960990bd050bb0fdf7222f3decd0a55008e32a6aa3c9062051c4cba92a7a3b178b24567412d43cdd2f882fa5addddd726fe3e208d2c26d733a773a597abb749714df7256ead5105fa6e7b3650de236b50"

var pkcs1MismatchKeyTests = []struct {
	hexKey        string
	errorContains string
}{
	{hexKey: hexPKCS1TestPKCS8Key, errorContains: "use ParsePKCS8PrivateKey instead"},
	{hexKey: hexPKCS1TestECKey, errorContains: "use ParseECPrivateKey instead"},
}

func TestPKCS1MismatchKeyFormat(t *testing.T) {
	for i, test := range pkcs1MismatchKeyTests {
		derBytes, _ := hex.DecodeString(test.hexKey)
		_, err := ParsePKCS1PrivateKey(derBytes)
		if !strings.Contains(err.Error(), test.errorContains) {
			t.Errorf("#%d: expected error containing %q, got %s", i, test.errorContains, err)
		}
	}
}
