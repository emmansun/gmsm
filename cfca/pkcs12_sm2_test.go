package cfca

import (
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var v2exKeyPem = `-----BEGIN CFCA KEY-----
MIIDSQIBATBHBgoqgRzPVQYBBAIBBgcqgRzPVQFoBDDkLvKllj9ZWhaKU6MSnxBBV5yaF3tEcOk1
vQniWyVzyaQA4F3j/YvDJwEoE8gOF/swggL5BgoqgRzPVQYBBAIBBIIC6TCCAuUwggKJoAMCAQIC
BRBAmQgJMAwGCCqBHM9VAYN1BQAwXDELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFu
Y2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEbMBkGA1UEAwwSQ0ZDQSBURVNUIFNNMiBPQ0Ex
MB4XDTIwMTExOTA4MzExOFoXDTI1MTExOTA4MzExOFowgYkxCzAJBgNVBAYTAkNOMRcwFQYDVQQK
DA5DRkNBIFRFU1QgT0NBMTENMAsGA1UECwwEUFNCQzEZMBcGA1UECwwQT3JnYW5pemF0aW9uYWwt
MjE3MDUGA1UEAwwuMDUxQOmCruWCqOe6v+S4iuaUtuWNleWVhuaIt0BONTEwMTEzMDAwMTg4NzhA
MTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABJVRC63OKfcL4H324rDOdb4SSlbAjoJDXnK0qmwX
Z59FWmiSqt3ipreljKew4QynjTgR/yfp9yjNgNU8G5pkYdujggEGMIIBAjAfBgNVHSMEGDAWgBRr
/hjaj0I6prhtsy6Igzo0osEw4TAMBgNVHRMBAf8EAjAAMEgGA1UdIARBMD8wPQYIYIEchu8qAQEw
MTAvBggrBgEFBQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xNC5odG0wOQYDVR0f
BDIwMDAuoCygKoYoaHR0cDovL3VjcmwuY2ZjYS5jb20uY24vU00yL2NybDE0MzU2LmNybDAOBgNV
HQ8BAf8EBAMCBsAwHQYDVR0OBBYEFPiGPZT0oTuRXvkyGoOgviNEWnc1MB0GA1UdJQQWMBQGCCsG
AQUFBwMCBggrBgEFBQcDBDAMBggqgRzPVQGDdQUAA0gAMEUCIQCJDSsVPfhr+gnDASMj5Syt+hxs
amHygPecjCLbcdFQQgIgSXC4musF5Fnj/CpNTqvk9+56FuINkATGS8xRh7kzKBE=
-----END CFCA KEY-----
`

var cfcasm2oca1 = `-----BEGIN CERTIFICATE-----
MIICTTCCAfKgAwIBAgIKZCTXgL0MKPOtBzAMBggqgRzPVQGDdQUAMF0xCzAJBgNV
BAYTAkNOMTAwLgYDVQQKDCdDaGluYSBGaW5hbmNpYWwgQ2VydGlmaWNhdGlvbiBB
dXRob3JpdHkxHDAaBgNVBAMME0NGQ0EgVEVTVCBDUyBTTTIgQ0EwHhcNMTIxMjI1
MTIyNTA2WhcNMzIwNzIzMTIyNTA2WjBcMQswCQYDVQQGEwJDTjEwMC4GA1UECgwn
Q2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRswGQYDVQQD
DBJDRkNBIFRFU1QgU00yIE9DQTEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQz
uFgJbedY55u6NToJElGWzPT+9UF1dxcopnerNO3fqRd4C1lDzz9LJZSfmMyNYaky
YC+6zh9G6/aPXW1Od/RFo4GYMIGVMB8GA1UdIwQYMBaAFLXYkG9c8Ngz0mO9frLD
jcZPEnphMAwGA1UdEwQFMAMBAf8wOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovLzIx
MC43NC40Mi4zL3Rlc3RyY2EvU00yL2NybDEuY3JsMAsGA1UdDwQEAwIBBjAdBgNV
HQ4EFgQUa/4Y2o9COqa4bbMuiIM6NKLBMOEwDAYIKoEcz1UBg3UFAANHADBEAiAR
kDmkQ0Clio48994IUs63nA8k652O2C4+7EQs1SSbuAIgcwNUrHJyEYX8xT5BKl9T
lJOefzCNNJW5Z0f3Y/SjaG0=
-----END CERTIFICATE-----
`

func parseTestKeyAndCert() (*sm2.PrivateKey, *smx509.Certificate, error) {
	password := []byte("123456")
	var block *pem.Block
	block, rest := pem.Decode([]byte(v2exKeyPem))
	if len(rest) != 0 {
		return nil, nil, errors.New("unexpected remaining PEM block during decode")
	}
	return ParseSM2(password, block.Bytes)
}

func TestParseSM2(t *testing.T) {
	cases := []struct {
		pem      string
		password []byte
	}{
		{
			v2exKeyPem,
			[]byte("123456"),
		},
		{
			`-----BEGIN CFCA KEY-----
MIIDmwIBATBHBgoqgRzPVQYBBAIBBgcqgRzPVQFoBDAjEsMB1LZrH4B5zBJQLh/S3vLTegY5twIU
lKu80vkB3XLfImABwhYVzFkjfJY1lWEwggNLBgoqgRzPVQYBBAIBBIIDOzCCAzcwggLaoAMCAQIC
BUQmAVGGMAwGCCqBHM9VAYN1BQAwXDELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFu
Y2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEbMBkGA1UEAwwSQ0ZDQSBBQ1MgU00yIE9DQTMx
MB4XDTIxMDcyMTA5NTMxMloXDTIxMDkyMTA5NTMxMlowbDELMAkGA1UEBhMCQ04xEzARBgNVBAoM
CkNGQ0EgT0NBMzExDzANBgNVBAsMBnlzZXBheTEVMBMGA1UECwwMSW5kaXZpZHVhbC0xMSAwHgYD
VQQDDBcwNTFAdGVzdF9zbTJAdGVzdF9zbTJAMjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABIex
X8bD+NRAEyP9mKl8/OKHHfogP82NobcifE9zyFlH0MPyMyXnjMT4FBQ1HPGRTExIUvnnS1GnuG0E
gtF58oCjggF1MIIBcTBsBggrBgEFBQcBAQRgMF4wKAYIKwYBBQUHMAGGHGh0dHA6Ly9vY3NwLmNm
Y2EuY29tLmNuL29jc3AwMgYIKwYBBQUHMAKGJmh0dHA6Ly9jcmwuY2ZjYS5jb20uY24vb2NhMzEv
b2NhMzEuY2VyMB8GA1UdIwQYMBaAFAjY0SbESH2c7KyY6fF/YrmAzqlFMAkGA1UdEwQCMAAwSAYD
VR0gBEEwPzA9BghggRyG7yoBBDAxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmNmY2EuY29tLmNu
L3VzL3VzLTE0Lmh0bTA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3JsLmNmY2EuY29tLmNuL29j
YTMxL1NNMi9jcmwxNDQwLmNybDAOBgNVHQ8BAf8EBAMCBsAwHQYDVR0OBBYEFJDoMEr89lXvtODi
obIvu3LOpoiFMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAMBggqgRzPVQGDdQUAA0kA
MEYCIQCV2YwNr90ad1E5mZqzmdkU0E1CWie9K0lsml012slavgIhAM/++u/l1x5cCIPZsCOYrIy2
0N8+aiLInpgEnkw3wQMt
-----END CFCA KEY-----
`,
			[]byte("ys123456"),
		},
	}

	for _, c := range cases {
		block, _ := pem.Decode([]byte(c.pem))
		if block == nil {
			t.Fatal("failed to decode PEM block")
		}
		priv, cert, err := ParseSM2(c.password, block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if priv == nil {
			t.Fatal("failed to parse private key")
		}
		if cert == nil {
			t.Fatal("failed to parse certificate")
		}
		if !priv.PublicKey.Equal(cert.PublicKey) {
			t.Fatal("public key mismatch")
		}
	}
}

func TestMarshalSM2(t *testing.T) {
	password := []byte("changeit")
	priv, cert, err := parseTestKeyAndCert()
	if err != nil {
		t.Fatal(err)
	}
	rootca1, err := smx509.ParseCertificatePEM([]byte(cfcasm2oca1))
	if err != nil {
		t.Fatal(err)
	}
	err = rootca1.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatal(err)
	}
	result, err := MarshalSM2(password, priv, cert)
	if err != nil {
		t.Fatal(err)
	}

	priv1, cert1, err := ParseSM2(password, result)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(priv1) {
		t.Fatal("not same private key")
	}
	if !cert.Equal(cert1) {
		t.Fatal("not same certficate")
	}
}

func TestParseSM2WithInvalidOID(t *testing.T) {
	password := []byte("changeit")
	testcases := []string{
		"308203490201013047060a2a811ccf55060104020906072a811ccf5501680430016ca58c339f32f5bbe2b0491d5087c9b5de0f5aef4b4d0726941a0c21d9795f51e802f2a1596cc909d1638067ca28cc308202f9060a2a811ccf550601040201048202e9308202e530820289a00302010202051040990809300c06082a811ccf550183750500305c310b300906035504061302434e3130302e060355040a0c274368696e612046696e616e6369616c2043657274696669636174696f6e20417574686f72697479311b301906035504030c1243464341205445535420534d32204f434131301e170d3230313131393038333131385a170d3235313131393038333131385a308189310b300906035504061302434e31173015060355040a0c0e434643412054455354204f434131310d300b060355040b0c045053424331193017060355040b0c104f7267616e697a6174696f6e616c2d323137303506035504030c2e30353140e982aee582a8e7babfe4b88ae694b6e58d95e59586e688b7404e353130313133303030313838373840313059301306072a8648ce3d020106082a811ccf5501822d0342000495510badce29f70be07df6e2b0ce75be124a56c08e82435e72b4aa6c17679f455a6892aadde2a6b7a58ca7b0e10ca78d3811ff27e9f728cd80d53c1b9a6461dba382010630820102301f0603551d230418301680146bfe18da8f423aa6b86db32e88833a34a2c130e1300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30390603551d1f04323030302ea02ca02a8628687474703a2f2f7563726c2e636663612e636f6d2e636e2f534d322f63726c31343335362e63726c300e0603551d0f0101ff0404030206c0301d0603551d0e04160414f8863d94f4a13b915ef9321a83a0be23445a7735301d0603551d250416301406082b0601050507030206082b06010505070304300c06082a811ccf5501837505000348003045022100890d2b153df86bfa09c3012323e52cadfa1c6c6a61f280f79c8c22db71d1504202204970b89aeb05e459e3fc2a4d4eabe4f7ee7a16e20d9004c64bcc5187b9332811",
		"308203490201013047060a2a811ccf55060104020106072a811ccf5501680430016ca58c339f32f5bbe2b0491d5087c9b5de0f5aef4b4d0726941a0c21d9795f51e802f2a1596cc909d1638067ca28cc308202f9060a2a811ccf550601040209048202e9308202e530820289a00302010202051040990809300c06082a811ccf550183750500305c310b300906035504061302434e3130302e060355040a0c274368696e612046696e616e6369616c2043657274696669636174696f6e20417574686f72697479311b301906035504030c1243464341205445535420534d32204f434131301e170d3230313131393038333131385a170d3235313131393038333131385a308189310b300906035504061302434e31173015060355040a0c0e434643412054455354204f434131310d300b060355040b0c045053424331193017060355040b0c104f7267616e697a6174696f6e616c2d323137303506035504030c2e30353140e982aee582a8e7babfe4b88ae694b6e58d95e59586e688b7404e353130313133303030313838373840313059301306072a8648ce3d020106082a811ccf5501822d0342000495510badce29f70be07df6e2b0ce75be124a56c08e82435e72b4aa6c17679f455a6892aadde2a6b7a58ca7b0e10ca78d3811ff27e9f728cd80d53c1b9a6461dba382010630820102301f0603551d230418301680146bfe18da8f423aa6b86db32e88833a34a2c130e1300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30390603551d1f04323030302ea02ca02a8628687474703a2f2f7563726c2e636663612e636f6d2e636e2f534d322f63726c31343335362e63726c300e0603551d0f0101ff0404030206c0301d0603551d0e04160414f8863d94f4a13b915ef9321a83a0be23445a7735301d0603551d250416301406082b0601050507030206082b06010505070304300c06082a811ccf5501837505000348003045022100890d2b153df86bfa09c3012323e52cadfa1c6c6a61f280f79c8c22db71d1504202204970b89aeb05e459e3fc2a4d4eabe4f7ee7a16e20d9004c64bcc5187b9332811",
		"3082034a0201013048060a2a811ccf55060104020106082a811ccf550168010430016ca58c339f32f5bbe2b0491d5087c9b5de0f5aef4b4d0726941a0c21d9795f51e802f2a1596cc909d1638067ca28cc308202f9060a2a811ccf550601040201048202e9308202e530820289a00302010202051040990809300c06082a811ccf550183750500305c310b300906035504061302434e3130302e060355040a0c274368696e612046696e616e6369616c2043657274696669636174696f6e20417574686f72697479311b301906035504030c1243464341205445535420534d32204f434131301e170d3230313131393038333131385a170d3235313131393038333131385a308189310b300906035504061302434e31173015060355040a0c0e434643412054455354204f434131310d300b060355040b0c045053424331193017060355040b0c104f7267616e697a6174696f6e616c2d323137303506035504030c2e30353140e982aee582a8e7babfe4b88ae694b6e58d95e59586e688b7404e353130313133303030313838373840313059301306072a8648ce3d020106082a811ccf5501822d0342000495510badce29f70be07df6e2b0ce75be124a56c08e82435e72b4aa6c17679f455a6892aadde2a6b7a58ca7b0e10ca78d3811ff27e9f728cd80d53c1b9a6461dba382010630820102301f0603551d230418301680146bfe18da8f423aa6b86db32e88833a34a2c130e1300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30390603551d1f04323030302ea02ca02a8628687474703a2f2f7563726c2e636663612e636f6d2e636e2f534d322f63726c31343335362e63726c300e0603551d0f0101ff0404030206c0301d0603551d0e04160414f8863d94f4a13b915ef9321a83a0be23445a7735301d0603551d250416301406082b0601050507030206082b06010505070304300c06082a811ccf5501837505000348003045022100890d2b153df86bfa09c3012323e52cadfa1c6c6a61f280f79c8c22db71d1504202204970b89aeb05e459e3fc2a4d4eabe4f7ee7a16e20d9004c64bcc5187b9332811",
	}
	for _, testcase := range testcases {
		der, _ := hex.DecodeString(testcase)
		_, _, err := ParseSM2(password, der)
		if err == nil {
			t.Fatal("expected error")
		}
	}
}

func TestParseSM2WithInvalidPwd(t *testing.T) {
	password := []byte("wrongpwd")
	der, _ := hex.DecodeString("308203490201013047060a2a811ccf55060104020106072a811ccf5501680430016ca58c339f32f5bbe2b0491d5087c9b5de0f5aef4b4d0726941a0c21d9795f51e802f2a1596cc909d1638067ca28cc308202f9060a2a811ccf550601040201048202e9308202e530820289a00302010202051040990809300c06082a811ccf550183750500305c310b300906035504061302434e3130302e060355040a0c274368696e612046696e616e6369616c2043657274696669636174696f6e20417574686f72697479311b301906035504030c1243464341205445535420534d32204f434131301e170d3230313131393038333131385a170d3235313131393038333131385a308189310b300906035504061302434e31173015060355040a0c0e434643412054455354204f434131310d300b060355040b0c045053424331193017060355040b0c104f7267616e697a6174696f6e616c2d323137303506035504030c2e30353140e982aee582a8e7babfe4b88ae694b6e58d95e59586e688b7404e353130313133303030313838373840313059301306072a8648ce3d020106082a811ccf5501822d0342000495510badce29f70be07df6e2b0ce75be124a56c08e82435e72b4aa6c17679f455a6892aadde2a6b7a58ca7b0e10ca78d3811ff27e9f728cd80d53c1b9a6461dba382010630820102301f0603551d230418301680146bfe18da8f423aa6b86db32e88833a34a2c130e1300c0603551d130101ff0402300030480603551d200441303f303d060860811c86ef2a01013031302f06082b060105050702011623687474703a2f2f7777772e636663612e636f6d2e636e2f75732f75732d31342e68746d30390603551d1f04323030302ea02ca02a8628687474703a2f2f7563726c2e636663612e636f6d2e636e2f534d322f63726c31343335362e63726c300e0603551d0f0101ff0404030206c0301d0603551d0e04160414f8863d94f4a13b915ef9321a83a0be23445a7735301d0603551d250416301406082b0601050507030206082b06010505070304300c06082a811ccf5501837505000348003045022100890d2b153df86bfa09c3012323e52cadfa1c6c6a61f280f79c8c22db71d1504202204970b89aeb05e459e3fc2a4d4eabe4f7ee7a16e20d9004c64bcc5187b9332811")
	_, _, err := ParseSM2(password, der)
	if err == nil || err.Error() != "cfca: failed to decrypt by SM4-CBC, please ensure the password is correct" {
		t.Fatal("cfca: failed to decrypt by SM4-CBC, please ensure the password is correct")
	}
}

func TestMarshalSM2WithoutPwd(t *testing.T) {
	priv, cert, err := parseTestKeyAndCert()
	if err != nil {
		t.Fatal(err)
	}
	_, err = MarshalSM2(nil, priv, cert)
	if err == nil || err.Error() != "cfca: invalid password" {
		t.Fatal(err)
	}
}

func TestParseSM2Mismatch(t *testing.T) {
	password := []byte("changeit")
	privKey, _ := hex.DecodeString("6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
	d := new(big.Int).SetBytes(privKey)
	testkey := new(sm2.PrivateKey)
	testkey.Curve = sm2.P256()
	testkey.D = d
	testkey.PublicKey.X, testkey.PublicKey.Y = testkey.ScalarBaseMult(testkey.D.Bytes())

	_, cert, err := parseTestKeyAndCert()
	if err != nil {
		t.Fatal(err)
	}

	result, err := MarshalSM2(password, testkey, cert)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ParseSM2(password, result)
	if err == nil || err.Error() != "cfca: public key and private key do not match" {
		t.Fatal("expected cfca: public key and private key do not match")
	}
}
