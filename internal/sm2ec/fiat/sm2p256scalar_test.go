package fiat_test

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/internal/sm2ec/fiat"
)

var ordN *big.Int

func init() {
	// n=115792089210356248756420345214020892766061623724957744567843809356293439045923
	// p-n=188730266966446886577384576996245946076
	ordN, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
}

var testValues = [20]string{
	"e576e1aefe41c42a634a6937982dd8ea60654c4d406ef141018072b8a8ee10ff",
	"374bf8d3ed1a35a109ccc73276e4fa3697d942eafcd514a82a985d0820f02645",
	"d62fd995bdc9ed6d405cad6a5cd48e0b92b465c2c8fbb7b14cc86e16e6dba6e8",
	"a8c28fe4b2c4abad3759ac3cb97c23eb0440273277f8d8be794eea0a2561357d",
	"f3bcfff783d0eb4de34bffd0c6290f75381bf715a1bc2b02ffbb58cc794ef1b7",
	"a08b119bb9bf49b2cda951de57df6e95f413a609aefa51eefa554a4906963942",
	"1b767aabebdf28a447de4c37b18d8c86e431c70acbb6d05eab459180e3731075",
	"40616625f9dd4e7c396106e539ed7891636acfb3ba7f80e72dc305b8cb2955d8",
	"3246e27330be55dc574e97a9e0c5ab6a476bb2b5422e8c47b2248a40504fc8a0",
	"aa54dec0a14ee69417186ff2711e59282d5badc3faa1528c4171e14baa525865",
	"408817dd964bd439aec08c3ebda707dc8ff969d25aef0ec0ba6085bc8da6996f",
	"99ed1792abdda9f0e43fd50c59a57b7f9c3c60d69c8046c71b67a1a71d9f7d55",
	"455705f9823bd5ba6f58c2a4dbdf6f10a0de1947a82c2653b00833ea39e26b5d",
	"b43fdba6043be8524bcc4cd6ab7d71534fcaf42869ab838e98608d5e9d801cf9",
	"c97498821b3b4db41239d1a3d47d49754e5e6b7bb7ae21d4eb0826bd5c0aeed6",
	"c0213f02d06c935b798594c9c3b4feaebea881205733a21484a48df4643fbde7",
	"313c9f7129eb1a09c385dc755aab9d88fcab79a7e4deaca68dd08d93fd68d252",
	"eb7b96f239402bd494dc258672cd4a1643ae9fe092ddaaca54f9e909548eaa90",
	"24567a167761a040aed80ea4655616b5aae5a0548b2a2a39a99bd4a6d7791610",
	"c79886c5cd9de1f2a0deee1c76cd8c38da7dcd401f59ec4bebbaf815006f2f71",
}

func p256OrderMulTest(t *testing.T, x, y, n *big.Int) {
	var scalar1 [32]byte
	var scalar2 [32]byte
	var scalar [32]byte
	x1 := new(big.Int).Mod(x, n)
	y1 := new(big.Int).Mod(y, n)
	ax := new(fiat.SM2P256OrderElement)
	ay := new(fiat.SM2P256OrderElement)
	res := new(fiat.SM2P256OrderElement)
	x1.FillBytes(scalar1[:])
	y1.FillBytes(scalar2[:])
	_, err := ax.SetBytes(scalar1[:])
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(scalar1[:], ax.Bytes()) {
		t.Errorf("x SetBytes/Bytes error, expected %v, got %v\n", hex.EncodeToString(scalar1[:]), hex.EncodeToString(ax.Bytes()))
	}
	_, err = ay.SetBytes(scalar2[:])
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(scalar2[:], ay.Bytes()) {
		t.Errorf("y SetBytes/Bytes error, expected %v, got %v\n", hex.EncodeToString(scalar2[:]), hex.EncodeToString(ay.Bytes()))
	}
	res = res.Mul(ax, ay)
	expected := new(big.Int).Mul(x1, y1)
	expected = expected.Mod(expected, n)
	expected.FillBytes(scalar[:])
	if !bytes.Equal(res.Bytes(), scalar[:]) {
		t.Errorf("expected %v, got %v\n", hex.EncodeToString(scalar[:]), hex.EncodeToString(res.Bytes()))
	}
}

func TestP256Mul(t *testing.T) {
	for i := 0; i < 20; i += 2 {
		x, _ := new(big.Int).SetString(testValues[i], 16)
		y, _ := new(big.Int).SetString(testValues[i+1], 16)
		p256OrderMulTest(t, x, y, ordN)
	}
}

func TestP256Square(t *testing.T) {
	var scalar [32]byte
	for i := 0; i < 20; i++ {
		x, _ := new(big.Int).SetString(testValues[i], 16)
		ax := new(fiat.SM2P256OrderElement)
		ax.SetBytes(x.Bytes())
		res := new(fiat.SM2P256OrderElement)
		res.Square(ax)
		expected := new(big.Int).Mul(x, x)
		expected = expected.Mod(expected, ordN)
		expected.FillBytes(scalar[:])
		if !bytes.Equal(res.Bytes(), scalar[:]) {
			t.Errorf("expected %v, got %v\n", hex.EncodeToString(scalar[:]), hex.EncodeToString(res.Bytes()))
		}
	}
}

func TestP256Add(t *testing.T) {
	var scalar [32]byte
	for i := 0; i < 20; i += 2 {
		x, _ := new(big.Int).SetString(testValues[i], 16)
		y, _ := new(big.Int).SetString(testValues[i+1], 16)
		expected := new(big.Int).Add(x, y)
		expected = expected.Mod(expected, ordN)
		expected.FillBytes(scalar[:])

		ax := new(fiat.SM2P256OrderElement)
		ax.SetBytes(x.Bytes())

		ay := new(fiat.SM2P256OrderElement)
		ay.SetBytes(y.Bytes())

		res := new(fiat.SM2P256OrderElement)
		res.Add(ax, ay)

		if !bytes.Equal(res.Bytes(), scalar[:]) {
			t.Errorf("expected %v, got %v\n", hex.EncodeToString(scalar[:]), hex.EncodeToString(res.Bytes()))
		}
	}
}
