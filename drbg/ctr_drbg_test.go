package drbg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/sm4"
)

var ctrtests = []struct {
	gm                    bool
	cipherProvider        func(key []byte) (cipher.Block, error)
	keyLen                int
	entropyInput          string
	nonce                 string
	personalizationString string
	v0                    string
	key0                  string
	entropyInputReseed    string
	additionalInputReseed string
	v1                    string
	key1                  string
	additionalInput1      string
	v2                    string
	key2                  string
	additionalInput2      string
	returnbits1           string
	v3                    string
	key3                  string
}{
	{ // AES-128, without additional input
		false,
		aes.NewCipher,
		16,
		"0f65da13dca407999d4773c2b4a11d85",
		"5209e5b4ed82a234",
		"",
		"80941680713df715056fb2a3d2e998b2",
		"0c42ea6804303954deb197a07e6dbdd2",
		"1dea0a12c52bf64339dd291c80d8ca89",
		"",
		"f2bacbb233252fba35fb0582f9286179", // v1
		"32fbfd0109f364ed21ef21a6e5c763e7", //key1
		"",
		"99003d630bba500fe17c37f8c7331bf6", // v2
		"757c8eb766f9aaa4650d6500b58624a3", //key2
		"",
		"2859cc468a76b08661ffd23b28547ffd0997ad526a0f51261b99ed3a37bd407bf418dbe6c6c3e26ed0ddefcb7474d899bd99f3655427519fc5b4057bcaf306d4",
		"5907ab447a88e5106753507cc97e0fd5",
		"e421ff2445e04992faf36cf9a5eaf1f9",
	},
	{ // AES-128, without additional input
		false,
		aes.NewCipher,
		16,
		"c9b8d7eb0afa5889e7f9b78a50ed453c",
		"3058ba347ecd11b1",
		"",
		"b4e0180e3af0d99592249db33a29cc4e",
		"1621bebef7e9215078459ecc74baffbc",
		"643686b86266d9111f29eb389e1184b4",
		"",
		"7574911eeb85d56d385f0c8c99965c4a", // v1
		"a4c515266cb5986825a503b39d5f398c", //key1
		"",
		"abca3ea049e405d3826f43e54e08c8f7", // v2
		"edcdf23f60d3988a4d235798aa0d33a2", //key2
		"",
		"0a8ccadc1c5cbd20b8ce32f942505e654b91a4e9410e0ea627c961d632d3be71d6a7dfd64b8f70d28ff91869b92ced908b454936b6d18fcddd7fb77216ccc404",
		"1d57b4e09fd920d91877a0737559ee29",
		"e83e07722d26779d0b76a52a629b211b",
	},
	{ // AES-128, with additional input
		false,
		aes.NewCipher,
		16,
		"285da6cf762552634636bfee3400b156",
		"8f8bada74820cb43",
		"",
		"ad2af7e4c84337cfc3116d59f02c54a8", // v0
		"c92780982442d348cc7363dfc96a999d", // key0
		"b4699b33354a83bfed115f770f32db0b", // EntropyInputReseed
		"38bfec9a10e6e40c106841dae48dc3b8", // AdditionalInputReseed
		"923f37427a8e10bf945249a5b790769a", // v1
		"57004c8a776f5c702e83ff56acc32dcc", // key1
		"629ead5bacfac8235711ffeb22f57558", // AdditionalInput1
		"7ade619ed91092987d8a1d244605f85f", // v2
		"3b5f92f511c10fef2f640de2cd8c9049", // key2
		"dd8a02ee668ca3e03949b38cb6e6b4df", // AdditionalInput2
		"e555aa4432bde04dcf0f0b03ead187b31df06653d444234b5c1bfc11b224285f2fb2b6cdd5a9ae6f13d99bd02c3c9fe9c3c1be46a600f5f757ab4574af893501",
		"f5dac2375e820f797c6f1258147d8ea7", // v3
		"6bc01c1518fe9f9dfbbb08d97c34db1e", // key3
	},
	{ // AES-192, without additional input
		false,
		aes.NewCipher,
		24,
		"b11d8b104a7ced9b9f37e5d92ad3dfcbb817552b1ae88f6a",
		"017510f270c66586a51313eadc32b07e",
		"",
		"9e5767ab537fe663c71e4054ba618c8d", // v0
		"b9b3d73bc0c784a7d78db344109707c73abbff7dc2dfa864", // key0
		"6d14cfb36f30c9c1a1ba0e0a32c2f99d1b47f219a3a8ac14", // EntropyInputReseed
		"",                                 // AdditionalInputReseed
		"c8563c5a4adc3b579f79f898c4b69854", // v1
		"3e18d4984d454e5f986e49bfa7a569dab3667ece8130cba1", // key1
		"",                                 // AdditionalInput1
		"087a3112e191f60619acae2a556f333b", // v2
		"b42a24cbb9e8c014bb65350afa28a67b273a41e599bde5b8", // key2
		"", // AdditionalInput2
		"53fbba563ae014ebc080767aab8452a9f36ce40bbf68f1a12dc0a6388c870c8dfa4250526cbc8c983fee6449903c6bd7c2c02e327680a66b464267edbc4e6797",
		"84f344f8277841e920464ca475b10276",                 // v3
		"1f5e987ac2259b7072867e4ae59167094d0162111062f6f8", // key3
	},
	{ // AES-192, with additional input
		false,
		aes.NewCipher,
		24,
		"3a09c9cc5e01f152ea2ed3021d49b4d6386aa6f04521ebde",
		"490bd4ee628cf9615035543e70fce4e2",
		"",
		"59a45ccbc3864f79b896c30d4a231d46", // v0
		"a4283dc9450ac97bf22c387082e3816728243473cedaa2af",                 // key0
		"df06e5668d41a6fa7660aef477eff7a0ffc0542c1cd406d5",                 // EntropyInputReseed
		"59b8c26626aab69e462752722f19450d12e2c0e959882d4d06ef4177e396855d", // AdditionalInputReseed
		"5857d49a1552923931926dca1682fbc2",                                 // v1
		"9c4d7784fe341619e21f2535d404866df3b75e9a7940d471",                 // key1
		"28e57a9128e479985cce391e98127fd126f37ad0f317fd5f97b8c18e762f360b", // AdditionalInput1
		"bb8ed7bcbe1203be861b8e6570fe116b",                                 // v2
		"6a8fddde995255f89ea3c9454cc481045ff0e16ce5a34693",                 // key2
		"d488672b52e867816178369f542190685bbe8672720c1943d8a4378cc9b9dd0c", // AdditionalInput2
		"5c233e2850e4981bab0f6513a76ca2c9f9f97b89b7fedd3d9aaffecf305d89fd5306cf24715895ad9ba7dac8c389fd87f95b4973003150871fa281e962f270cb",
		"1cf82a0638c421bb43401943498d0f88",                 // v3
		"5dec9ad1f5f3d0e7bb59ae581097a3f616e443e4f5bd804a", // key3
	},
	{ // AES-256, without additional input
		false,
		aes.NewCipher,
		32,
		"2d4c9f46b981c6a0b2b5d8c69391e569ff13851437ebc0fc00d616340252fed5",
		"0bf814b411f65ec4866be1abb59d3c32",
		"",
		"446ce986bd722ad1a514ebb7d274ec99", // v0
		"d64160c3e965f377caef625c7eb21dd37728bcf84bfc23b92e267611feaffda8", // key0
		"93500fae4fa32b86033b7a7bac9d37e710dcc67ca266bc8607d665937766d207", // EntropyInputReseed
		"",                                 // AdditionalInputReseed
		"0b8e38a54036f1ba80a2880d4f17bb09", // v1
		"50d9feb33fc77303b83232b7deded04f1bfa4afaa937712f88458d6b64c046c5", // key1
		"",                                 // AdditionalInput1
		"84b0a849c5459e27fe7f8c5db26fa13d", // v2
		"a2203a6f082ecdc0cd38f0b3b19f1a8cd6a5f110a13bb488c1e70f9f95a93024", // key2
		"", // AdditionalInput2
		"322dd28670e75c0ea638f3cb68d6a9d6e50ddfd052b772a7b1d78263a7b8978b6740c2b65a9550c3a76325866fa97e16d74006bc96f26249b9f0a90d076f08e5",
		"de67dd5f9a431fc46dd1825cd1a2bff3",                                 // v3
		"de721178a341a85eb54a2f7e2b3cd4bcc201417e739eb183fa958f9af8535b2c", // key3
	},
	{ // AES-256, with additional input
		false,
		aes.NewCipher,
		32,
		"6f60f0f9d486bc23e1223b934e61c0c78ae9232fa2e9a87c6dacd447c3f10e9e",
		"401e3f87762fa8a14ab232ccb8480a2f",
		"",
		"ee534dcfd9d2be3a3f9c65a6c5f599b0", // v0
		"6d9aa2e029466438d3e4c22530bd071dbe57b549b87370957b28da8ae083f8d6", // key0
		"350be52552a65a804a106543ebb7dd046cffae104e4e8b2f18936d564d3c1950", // EntropyInputReseed
		"7a3688adb1cfb6c03264e2762ece96bfe4daf9558fabf74d7fff203c08b4dd9f", // AdditionalInputReseed
		"433725f6c4b8c662c3b2db4b75f38d86",                                 // v1
		"b5953178a900b2fcf052b5cbc1d882ea944da2965e84fef59c4919bb4d5c892d", // key1
		"67cf4a56d081c53670f257c25557014cd5e8b0e919aa58f23d6861b10b00ea80", // AdditionalInput1
		"2c342b2ab12bd3484e4660b8dd5f85eb",                                 // v2
		"b2b9e9f1ffcfd84c050445f93dfad90d6ca240494bbed5d44a0deb38fbaeb751", // key2
		"648d4a229198b43f33dd7dd8426650be11c5656adcdf913bb3ee5eb49a2a3892", // AdditionalInput2
		"2d819fb9fee38bfc3f15a07ef0e183ff36db5d3184cea1d24e796ba103687415abe6d9f2c59a11931439a3d14f45fc3f4345f331a0675a3477eaf7cd89107e37",
		"a9729f842063b9464e74018c0ab30df3",                                 // v3
		"770600434fe0af64e045f5530e2b9732da9e3b4c3af342994a4f1f7ee5c4144e", // key3
	},
	{ // SM4-128, without additional input
		true,
		sm4.NewCipher,
		16,
		"2d4c9f46b981c6a0b2b5d8c69391e569ff13851437ebc0fc00d616340252fed5",
		"0bf814b411f65ec4866be1abb59d3c32",
		"",
		"044f9ff3b7e8ad2b60a7b2c05fe6b5b7",
		"7fce60b97d8ceb60506bff1d37b1a936",
		"93500fae4fa32b86033b7a7bac9d37e710dcc67ca266bc8607d665937766d207",
		"",
		"8bd44b2e39f8186497f889c73555797d", // v1
		"02b9a8f88124bd9cec909e1fd7ec9971", //key1
		"",
		"fbc91ad876ba3a84588be2f358b9e13c", // v2
		"4804b2a1a971ca729abff5bada051cf6", //key2
		"",
		"e732a524de8ad239aa293ac8ae588f9d",
		"ce60250d77048bdbe48ade354b6869f6",
		"6788e31ae27aae09a14aed967ce8b219",
	},
	{ // SM4-128, with additional input
		false,
		sm4.NewCipher,
		16,
		"6f60f0f9d486bc23e1223b934e61c0c78ae9232fa2e9a87c6dacd447c3f10e9e",
		"401e3f87762fa8a14ab232ccb8480a2f",
		"",
		"5e8c10afe142dc9c8caf35411b38730a", // v0
		"d72aefa9fd527383ad418f6158627feb", // key0
		"350be52552a65a804a106543ebb7dd046cffae104e4e8b2f18936d564d3c1950", // EntropyInputReseed
		"7a3688adb1cfb6c03264e2762ece96bfe4daf9558fabf74d7fff203c08b4dd9f", // AdditionalInputReseed
		"c00836da0fd780cdc81dabec80e344ce",                                 // v1
		"f5f3abdeff30df22f4866d83cd96bc1b",                                 // key1
		"67cf4a56d081c53670f257c25557014cd5e8b0e919aa58f23d6861b10b00ea80", // AdditionalInput1
		"6ddb205ec76567b31a07ee48437acebc",                                 // v2
		"5e23cbe8b97065102ca0d87bfd9ae0da",                                 // key2
		"648d4a229198b43f33dd7dd8426650be11c5656adcdf913bb3ee5eb49a2a3892", // AdditionalInput2
		"b0ac91f148efbdc3570d7e434aba8d24",
		"d1f029bb089613d836ddc6fe1d6fb96f", // v3
		"8adfe65e9137b18f060ae91e7a6224c1", // key3
	},
}

func TestCtrDRBG(t *testing.T) {
	for i, test := range ctrtests {
		entropyInput, _ := hex.DecodeString(test.entropyInput)
		nonce, _ := hex.DecodeString(test.nonce)
		personalizationString, _ := hex.DecodeString(test.personalizationString)
		v0, _ := hex.DecodeString(test.v0)
		key0, _ := hex.DecodeString(test.key0)
		hd, err := NewCtrDrbg(test.cipherProvider, test.keyLen, SECURITY_LEVEL_ONE, test.gm, entropyInput, nonce, personalizationString)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hd.v[:len(v0)], v0) {
			t.Errorf("case %v, not same v0 %s", i+1, hex.EncodeToString(hd.v))
		}
		if !bytes.Equal(hd.key[:len(key0)], key0) {
			t.Errorf("case %v, not same key0 %s", i+1, hex.EncodeToString(hd.key))
		}
		// Reseed
		entropyInputReseed, _ := hex.DecodeString(test.entropyInputReseed)
		additionalInputReseed, _ := hex.DecodeString(test.additionalInputReseed)
		v1, _ := hex.DecodeString(test.v1)
		key1, _ := hex.DecodeString(test.key1)
		err = hd.Reseed(entropyInputReseed, additionalInputReseed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(hd.v, v1) {
			t.Errorf("case %v, not same v1 %s", i+1, hex.EncodeToString(hd.v))
		}
		if !bytes.Equal(hd.key, key1) {
			t.Errorf("case %v, not same key1 %s", i+1, hex.EncodeToString(hd.key))
		}
		// Generate 1
		returnbits1, _ := hex.DecodeString(test.returnbits1)
		v2, _ := hex.DecodeString(test.v2)
		key2, _ := hex.DecodeString(test.key2)
		output := make([]byte, len(returnbits1))
		additionalInput1, _ := hex.DecodeString(test.additionalInput1)
		hd.Generate(output, additionalInput1)
		if !bytes.Equal(hd.v, v2) {
			t.Errorf("case %v, not same v2 %s", i+1, hex.EncodeToString(hd.v))
		}
		if !bytes.Equal(hd.key, key2) {
			t.Errorf("case %v, not same key2 %s", i+1, hex.EncodeToString(hd.key))
		}
		// Generate 2
		v3, _ := hex.DecodeString(test.v3)
		key3, _ := hex.DecodeString(test.key3)
		additionalInput2, _ := hex.DecodeString(test.additionalInput2)
		hd.Generate(output, additionalInput2)
		if !bytes.Equal(hd.v[:len(v0)], v3) {
			t.Errorf("case %v, not same v3 %s", i+1, hex.EncodeToString(hd.v))
		}
		if !bytes.Equal(hd.key, key3) {
			t.Errorf("case %v, not same key3 %s", i+1, hex.EncodeToString(hd.key))
		}
		if !bytes.Equal(returnbits1, output) {
			t.Errorf("case %v, not expected return bits %s", i+1, hex.EncodeToString(output))
		}
	}
}

func TestGmCtrDRBG_Validation(t *testing.T) {
	entropyInput := make([]byte, 64)
	_, err := NewCtrDrbg(sm4.NewCipher, 16, SECURITY_LEVEL_ONE, true, entropyInput[:16], entropyInput[16:24], nil)
	if err == nil {
		t.Fatalf("expected error here")
	}
	_, err = NewCtrDrbg(sm4.NewCipher, 16, SECURITY_LEVEL_ONE, true, entropyInput[:32], entropyInput[32:40], nil)
	if err == nil {
		t.Fatalf("expected error here")
	}
	hd, err := NewCtrDrbg(sm4.NewCipher, 16, SECURITY_LEVEL_ONE, true, entropyInput[:32], entropyInput[32:48], nil)
	if err != nil {
		t.Fatal(err)
	}
	err = hd.Reseed(entropyInput[:16], nil)
	if err == nil {
		t.Fatalf("expected error here")
	}
}
