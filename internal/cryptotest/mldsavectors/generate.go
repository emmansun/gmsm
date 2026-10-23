package mldsavectors

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/mldsa"
)

const fileName = "mldsa_semantics.json"

type signingKey interface {
	Bytes() []byte
	Public() crypto.PublicKey
	SignMessage(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
}

type parameters struct {
	name       string
	rows       int
	columns    int
	omega      int
	beta       int
	secretBits int
	newKey     func([]byte) (signingKey, error)
}

func keyCases(encoded []byte) []vectors.Case {
	return []vectors.Case{
		{TCID: 1, Comment: "canonical encoding round trip", Input: hex.EncodeToString(encoded), Result: "valid"},
		{TCID: 2, Comment: "empty input", Result: "invalid"},
		{TCID: 3, Comment: "one byte short", Input: hex.EncodeToString(encoded[:len(encoded)-1]), Result: "invalid"},
		{TCID: 4, Comment: "trailing byte", Input: hex.EncodeToString(append(bytes.Clone(encoded), 0)), Result: "invalid"},
	}
}

func buildGroups(parameter parameters) ([]vectors.Group, error) {
	seed := make([]byte, mldsa.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	key, err := parameter.newKey(seed)
	if err != nil {
		return nil, err
	}
	pub := key.Public().(interface{ Bytes() []byte }).Bytes()
	priv := key.Bytes()
	message := []byte{0x00, 0x01, 0x7f, 0x80, 0xff}
	sign := func(context []byte) ([]byte, error) {
		return key.SignMessage(bytes.NewReader(make([]byte, 32)), message, &mldsa.Options{Context: context})
	}
	signature, err := sign(nil)
	if err != nil {
		return nil, err
	}
	seedCases := []vectors.Case{
		{TCID: 1, Comment: "fixed seed, encoded public key as a regression pin", Input: hex.EncodeToString(seed), Expected: hex.EncodeToString(pub), Result: "valid"},
		{TCID: 2, Comment: "empty seed", Result: "invalid"},
		{TCID: 3, Comment: "seed one byte short", Input: hex.EncodeToString(seed[:31]), Result: "invalid"},
		{TCID: 4, Comment: "seed with trailing byte", Input: hex.EncodeToString(append(bytes.Clone(seed), 0)), Result: "invalid"},
	}
	publicCases := keyCases(pub)
	for _, value := range []byte{0, 0xff} {
		publicCases = append(publicCases, vectors.Case{TCID: len(publicCases) + 1, Comment: fmt.Sprintf("all-%02x public key encoding is canonical", value), Input: hex.EncodeToString(bytes.Repeat([]byte{value}, len(pub))), Result: "valid"})
	}
	privateCases := keyCases(priv)
	for _, offset := range []int{128, 128 + parameter.columns*256*parameter.secretBits/8} {
		changed := bytes.Clone(priv)
		changed[offset] |= byte((1 << parameter.secretBits) - 1)
		privateCases = append(privateCases, vectors.Case{TCID: len(privateCases) + 1, Comment: fmt.Sprintf("noncanonical secret coefficient at byte %d", offset), Input: hex.EncodeToString(changed), Result: "invalid"})
	}

	var verifyCases []vectors.Case
	addVerify := func(comment string, publicKey, msg, context, sig []byte, result string) {
		verifyCases = append(verifyCases, vectors.Case{TCID: len(verifyCases) + 1, Comment: comment, Pub: hex.EncodeToString(publicKey), Msg: hex.EncodeToString(msg), Context: hex.EncodeToString(context), Sig: hex.EncodeToString(sig), Result: result})
	}
	addVerify("fixed-seed valid signature", pub, message, nil, signature, "valid")
	addVerify("wrong message", pub, []byte("different message"), nil, signature, "invalid")
	addVerify("wrong context", pub, message, []byte{0}, signature, "invalid")
	addVerify("context exceeds 255 bytes", pub, message, make([]byte, 256), signature, "invalid")
	addVerify("empty signature", pub, message, nil, nil, "invalid")
	addVerify("signature one byte short", pub, message, nil, signature[:len(signature)-1], "invalid")
	addVerify("trailing signature byte", pub, message, nil, append(bytes.Clone(signature), 0), "invalid")
	changedChallenge := bytes.Clone(signature)
	changedChallenge[0] ^= 1
	addVerify("challenge hash bit flipped", pub, message, nil, changedChallenge, "invalid")
	otherKey, err := parameter.newKey(bytes.Repeat([]byte{0xa5}, 32))
	if err != nil {
		return nil, err
	}
	addVerify("signature under a different public key", otherKey.Public().(interface{ Bytes() []byte }).Bytes(), message, nil, signature, "invalid")
	challengeSize := map[string]int{"44": 32, "65": 48, "87": 64}[parameter.name]
	responseBits := 20
	if parameter.name == "44" {
		responseBits = 18
	}
	for _, encoded := range []int{0, parameter.beta} {
		changed := bytes.Clone(signature)
		changed[challengeSize] = byte(encoded)
		changed[challengeSize+1] = byte(encoded >> 8)
		mask := byte((1 << (responseBits - 16)) - 1)
		changed[challengeSize+2] = changed[challengeSize+2]&^mask | byte(encoded>>16)&mask
		addVerify(fmt.Sprintf("z norm reaches or exceeds gamma1-beta, encoded coefficient %d", encoded), pub, message, nil, changed, "invalid")
	}
	hintStart := len(signature) - parameter.omega - parameter.rows
	malformedHint := func() []byte {
		changed := bytes.Clone(signature)
		clear(changed[hintStart:])
		return changed
	}
	tooManyHints := malformedHint()
	tooManyHints[hintStart+parameter.omega] = byte(parameter.omega + 1)
	addVerify("hint counter exceeds omega", pub, message, nil, tooManyHints, "invalid")
	decreasingHints := malformedHint()
	decreasingHints[hintStart] = 5
	for row := range parameter.rows {
		decreasingHints[hintStart+parameter.omega+row] = 1
	}
	decreasingHints[hintStart+parameter.omega+1] = 0
	addVerify("hint counters decrease", pub, message, nil, decreasingHints, "invalid")
	used := int(signature[len(signature)-1])
	if used >= parameter.omega {
		return nil, fmt.Errorf("ML-DSA-%s baseline needs unused hint space", parameter.name)
	}
	start, row := 0, 0
	for ; row < parameter.rows; row++ {
		end := int(signature[hintStart+parameter.omega+row])
		if end-start >= 2 {
			break
		}
		start = end
	}
	if row == parameter.rows {
		return nil, fmt.Errorf("ML-DSA-%s baseline needs two hints in one polynomial", parameter.name)
	}
	unsorted := bytes.Clone(signature)
	unsorted[hintStart+start], unsorted[hintStart+start+1] = unsorted[hintStart+start+1], unsorted[hintStart+start]
	addVerify("swapped hint indices preserve the decoded set but are noncanonical", pub, message, nil, unsorted, "invalid")
	duplicate := bytes.Clone(signature)
	copy(duplicate[hintStart+start+1:hintStart+used+1], signature[hintStart+start:hintStart+used])
	for index := row; index < parameter.rows; index++ {
		duplicate[hintStart+parameter.omega+index]++
	}
	addVerify("duplicate hint index preserves the decoded set but is noncanonical", pub, message, nil, duplicate, "invalid")
	padding := bytes.Clone(signature)
	padding[hintStart+used] = 1
	addVerify("unused hint padding is nonzero", pub, message, nil, padding, "invalid")

	var signCases []vectors.Case
	for _, length := range []int{0, 1, 255} {
		context := bytes.Repeat([]byte{0xa5}, length)
		contextSignature, err := sign(context)
		if err != nil {
			return nil, err
		}
		addVerify(fmt.Sprintf("valid context length %d", length), pub, message, context, contextSignature, "valid")
		signCases = append(signCases, vectors.Case{TCID: len(signCases) + 1, Comment: fmt.Sprintf("deterministic signing with context length %d", length), Input: hex.EncodeToString(seed), Msg: hex.EncodeToString(message), Context: hex.EncodeToString(context), Pub: hex.EncodeToString(pub), Expected: hex.EncodeToString(contextSignature), Result: "valid"})
	}
	signCases = append(signCases,
		vectors.Case{TCID: len(signCases) + 1, Comment: "context length 256 must fail", Input: hex.EncodeToString(seed), Msg: hex.EncodeToString(message), Context: hex.EncodeToString(make([]byte, 256)), Result: "invalid"},
		vectors.Case{TCID: len(signCases) + 2, Comment: "short randomness reader must fail", Input: hex.EncodeToString(seed), Msg: hex.EncodeToString(message), Result: "invalid", Flags: []string{"ShortRandomness"}},
	)
	return []vectors.Group{
		{Type: "MLDSA" + parameter.name + "Seed", Tests: seedCases},
		{Type: "MLDSA" + parameter.name + "PublicKey", Tests: publicCases},
		{Type: "MLDSA" + parameter.name + "PrivateKey", Tests: privateCases},
		{Type: "MLDSA" + parameter.name + "Verify", Tests: verifyCases},
		{Type: "MLDSA" + parameter.name + "Sign", Tests: signCases},
	}, nil
}

func BuildSuite() (*vectors.Suite, error) {
	suite := &vectors.Suite{Schema: vectors.SemanticsSchema, Algorithm: "ML-DSA", Generator: "go test ./internal/cryptotest/mldsavectors -run TestVectorsUpToDate -update; fixed-seed library-generated regression baselines, FIPS 204 rejection predicates"}
	for _, parameter := range []parameters{
		{"44", 4, 4, 80, 78, 3, func(seed []byte) (signingKey, error) { return mldsa.NewKey44(seed) }},
		{"65", 6, 5, 55, 196, 4, func(seed []byte) (signingKey, error) { return mldsa.NewKey65(seed) }},
		{"87", 8, 7, 75, 120, 3, func(seed []byte) (signingKey, error) { return mldsa.NewKey87(seed) }},
	} {
		groups, err := buildGroups(parameter)
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
