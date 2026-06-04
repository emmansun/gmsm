//go:build amd64 && !purego

package sm4

import (
	"fmt"
	"testing"
)

func TestGcmSm4Init(t *testing.T) {
	expendedHex := "a3db8c13e63ad58106e2a32959fad410a5392f3abfc00191a5392f3abfc001910c4b5d4416e6746c2c487ef61f01819f200323b209e7f5f3200323b209e7f5f31fc3fdc71504490c0a5f6c24e7a2d0be159c91e3f2a699b2159c91e3f2a699b28496ff6b0801db5e93a9963e426c9618173f69554a6d4d46173f69554a6d4d4650a174a4b518961329a304696d059054790270cdd81d0647790270cdd81d064795c5b74db0d6c213c8984b421897287c5d5dfc0fa841ea6f5d5dfc0fa841ea6f9208acefd693f27fc7223dce2c483080552a9121fadbc2ff552a9121fadbc2ffa71fa73ca660289b7022aadefef73efcd73d0de258971667d73d0de258971667"
	key := make([]byte, 16)
	c, err := newCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	var bytesProductTable [256]byte

	switch c := c.(type) {
	case *sm4CipherNIGCM:
		gcmSm4Init(&bytesProductTable, c.enc[:], INST_SM4)
		if fmt.Sprintf("%x", bytesProductTable[:]) != expendedHex {
			t.Errorf("got %x, want %s", bytesProductTable[:], expendedHex)
		}
	case *sm4CipherGCM:
		gcmSm4Init(&bytesProductTable, c.enc[:], INST_AES)
		if fmt.Sprintf("%x", bytesProductTable[:]) != expendedHex {
			t.Errorf("got %x, want %s", bytesProductTable[:], expendedHex)
		}
	default:
		t.Fatalf("unexpected cipher type: %T", c)
	}
}
