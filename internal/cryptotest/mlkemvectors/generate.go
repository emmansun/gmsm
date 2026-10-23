package mlkemvectors

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/mlkem"
)

const fileName = "mlkem_semantics.json"

func material(parameter string, seed []byte) (pub, priv, ciphertext, shared []byte, err error) {
	var message [32]byte
	for index := range message {
		message[index] = byte(index + 64)
	}
	switch parameter {
	case "512":
		key, err := mlkem.NewDecapsulationKeyFromSeed512(seed)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		shared, ciphertext = key.EncapsulationKey().EncapsulateInternal(&message)
		return key.EncapsulationKey().Bytes(), key.Bytes(), ciphertext, shared, nil
	case "768":
		key, err := mlkem.NewDecapsulationKeyFromSeed768(seed)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		shared, ciphertext = key.EncapsulationKey().EncapsulateInternal(&message)
		return key.EncapsulationKey().Bytes(), key.Bytes(), ciphertext, shared, nil
	case "1024":
		key, err := mlkem.NewDecapsulationKeyFromSeed1024(seed)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		shared, ciphertext = key.EncapsulationKey().EncapsulateInternal(&message)
		return key.EncapsulationKey().Bytes(), key.Bytes(), ciphertext, shared, nil
	}
	return nil, nil, nil, nil, fmt.Errorf("unknown ML-KEM parameter %q", parameter)
}

func coefficient(input []byte, index, value int) []byte {
	output := bytes.Clone(input)
	offset := index / 2 * 3
	if index%2 == 0 {
		output[offset] = byte(value)
		output[offset+1] = output[offset+1]&0xf0 | byte(value>>8)
	} else {
		output[offset+1] = output[offset+1]&0x0f | byte(value<<4)
		output[offset+2] = byte(value >> 4)
	}
	return output
}

func keyCases(encoded []byte) []vectors.Case {
	return []vectors.Case{
		{TCID: 1, Comment: "canonical encoding round trip", Input: hex.EncodeToString(encoded), Result: "valid"},
		{TCID: 2, Comment: "empty input", Result: "invalid"},
		{TCID: 3, Comment: "one byte short", Input: hex.EncodeToString(encoded[:len(encoded)-1]), Result: "invalid"},
		{TCID: 4, Comment: "trailing byte", Input: hex.EncodeToString(append(bytes.Clone(encoded), 0)), Result: "invalid"},
	}
}

func buildGroups(parameter string, dimension int) ([]vectors.Group, error) {
	seed := make([]byte, mlkem.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	pub, priv, ciphertext, shared, err := material(parameter, seed)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 32)
	for index := range message {
		message[index] = byte(index + 64)
	}
	pubHash := sha3.Sum256(pub)
	expectedShared := sha3.Sum512(append(message, pubHash[:]...))
	if !bytes.Equal(shared, expectedShared[:32]) {
		return nil, fmt.Errorf("ML-KEM-%s encapsulated key disagrees with FIPS 203 derivation", parameter)
	}
	seedCases := []vectors.Case{
		{TCID: 1, Comment: "fixed seed, SHA3-256 of expanded key as a regression pin", Input: hex.EncodeToString(seed), Expected: digest(priv), Result: "valid"},
		{TCID: 2, Comment: "empty seed", Result: "invalid"},
		{TCID: 3, Comment: "seed one byte short", Input: hex.EncodeToString(seed[:63]), Result: "invalid"},
		{TCID: 4, Comment: "seed with trailing byte", Input: hex.EncodeToString(append(bytes.Clone(seed), 0)), Result: "invalid"},
	}
	_, zeroPriv, _, _, err := material(parameter, make([]byte, mlkem.SeedSize))
	if err != nil {
		return nil, err
	}
	seedCases = append(seedCases, vectors.Case{TCID: 5, Comment: "all-zero seed is a valid deterministic input", Input: hex.EncodeToString(make([]byte, mlkem.SeedSize)), Expected: digest(zeroPriv), Result: "valid"})

	publicCases := keyCases(pub)
	for _, mutation := range []struct {
		name   string
		index  int
		value  int
		result string
	}{
		{"coefficient q-1 is canonical", 0, 3328, "valid"},
		{"first coefficient equals q", 0, 3329, "invalid"},
		{"second coefficient is 4095", 1, 4095, "invalid"},
		{"last polynomial coefficient equals q", dimension*256 - 1, 3329, "invalid"},
	} {
		publicCases = append(publicCases, vectors.Case{TCID: len(publicCases) + 1, Comment: mutation.name, Input: hex.EncodeToString(coefficient(pub, mutation.index, mutation.value)), Result: mutation.result})
	}
	publicCases = append(publicCases, vectors.Case{TCID: len(publicCases) + 1, Comment: "zero coefficients and rho are canonical", Input: hex.EncodeToString(make([]byte, len(pub))), Result: "valid"})

	privateCases := keyCases(priv)
	for _, index := range []int{0, 1, dimension*256 - 1} {
		privateCases = append(privateCases, vectors.Case{TCID: len(privateCases) + 1, Comment: fmt.Sprintf("secret coefficient %d equals q", index), Input: hex.EncodeToString(coefficient(priv, index, 3329)), Result: "invalid"})
	}
	badPublic := bytes.Clone(priv)
	copy(badPublic[384*dimension:], coefficient(pub, 0, 3329))
	badPublicHash := sha3.Sum256(badPublic[384*dimension : 384*dimension+len(pub)])
	copy(badPublic[len(priv)-64:], badPublicHash[:])
	privateCases = append(privateCases, vectors.Case{TCID: len(privateCases) + 1, Comment: "embedded public key is noncanonical even with matching H(ek)", Input: hex.EncodeToString(badPublic), Result: "invalid"})
	badHash := bytes.Clone(priv)
	badHash[len(priv)-64] ^= 1
	privateCases = append(privateCases, vectors.Case{TCID: len(privateCases) + 1, Comment: "inconsistent H(ek)", Input: hex.EncodeToString(badHash), Result: "invalid"})
	changedRejectionSeed := bytes.Clone(priv)
	changedRejectionSeed[len(priv)-1] ^= 1
	privateCases = append(privateCases, vectors.Case{TCID: len(privateCases) + 1, Comment: "z is unrestricted seed material", Input: hex.EncodeToString(changedRejectionSeed), Result: "valid"})

	decapsulateCases := []vectors.Case{
		{TCID: 1, Comment: "encapsulation with fixed message, shared key independently derived", Input: hex.EncodeToString(seed), Ciphertext: hex.EncodeToString(ciphertext), Expected: hex.EncodeToString(expectedShared[:32]), Result: "valid"},
	}
	for _, length := range []int{0, 1, len(ciphertext) - 1, len(ciphertext) + 1} {
		decapsulateCases = append(decapsulateCases, vectors.Case{TCID: len(decapsulateCases) + 1, Comment: fmt.Sprintf("ciphertext length %d must return an error", length), Input: hex.EncodeToString(seed), Ciphertext: hex.EncodeToString(make([]byte, length)), Result: "invalid"})
	}
	mutations := [][]byte{make([]byte, len(ciphertext)), bytes.Repeat([]byte{0xff}, len(ciphertext))}
	for _, offset := range []int{0, len(ciphertext) / 2, len(ciphertext) - 1} {
		changed := bytes.Clone(ciphertext)
		changed[offset] ^= 0x80
		mutations = append(mutations, changed)
	}
	for index, changed := range mutations {
		rejection := sha3.NewSHAKE256()
		rejection.Write(seed[32:])
		rejection.Write(changed)
		expected := make([]byte, 32)
		rejection.Read(expected)
		decapsulateCases = append(decapsulateCases, vectors.Case{TCID: len(decapsulateCases) + 1, Comment: fmt.Sprintf("implicit rejection %d: SHAKE256(z || c, 32), no error", index+1), Input: hex.EncodeToString(seed), Ciphertext: hex.EncodeToString(changed), Expected: hex.EncodeToString(expected), Result: "valid", Flags: []string{"ImplicitRejection"}})
	}
	return []vectors.Group{
		{Type: "MLKEM" + parameter + "Seed", Tests: seedCases},
		{Type: "MLKEM" + parameter + "PublicKey", Tests: publicCases},
		{Type: "MLKEM" + parameter + "PrivateKey", Tests: privateCases},
		{Type: "MLKEM" + parameter + "Decapsulate", Tests: decapsulateCases},
	}, nil
}

func digest(input []byte) string {
	sum := sha3.Sum256(input)
	return hex.EncodeToString(sum[:])
}

func BuildSuite() (*vectors.Suite, error) {
	suite := &vectors.Suite{Schema: vectors.SemanticsSchema, Algorithm: "ML-KEM", Generator: "go test ./internal/cryptotest/mlkemvectors -run TestVectorsUpToDate -update; fixed-seed library-generated baselines, FIPS 203 key and rejection derivations"}
	for _, parameter := range []struct {
		name      string
		dimension int
	}{{"512", 2}, {"768", 3}, {"1024", 4}} {
		groups, err := buildGroups(parameter.name, parameter.dimension)
		if err != nil {
			return nil, err
		}
		suite.Groups = append(suite.Groups, groups...)
	}
	return suite, suite.Validate()
}

func MarshalSuite(suite *vectors.Suite) ([]byte, error) {
	encoded, err := json.MarshalIndent(suite, "", "  ")
	return append(encoded, '\n'), err
}
