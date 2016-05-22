package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	. "github.com/nikkolasg/learning/crypto/util"

	"github.com/bford/golang-x-crypto/ed25519"
	"github.com/bford/golang-x-crypto/ed25519/cosi"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	cryptoEd "github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/crypto/nist"
)

var SEED1 []byte
var SEED2 []byte

func init() {
	SEED1, _ = hex.DecodeString("3aed8a2f6ca4c385ad90dbebcfef29ceaea9e2df09530399dc82245c96d643945da80212409bad9c4af7511fdc5caf8fe196ff669cbb51334c4070d8e798df0a")
	SEED2, _ = hex.DecodeString("4afcd0cc48d60d94db58fbc5de2261513750b10e3a5f0c8cec2978f6d2c008b6d182674965dbff66725f472cd10d9ba82d13228af96e4636ff0faf5882eb8504")
}

func main() {
	testCosi()
	//eddsa()
}

func testCosi() {
	suite := cryptoEd.NewAES128SHA256Ed25519(false)
	msg := []byte("Hello World")
	// Create keypairs for the two cosigners.
	_, priKey1, _ := ed25519.GenerateKey(nil)
	_, priKey2, _ := ed25519.GenerateKey(nil)
	// XXX NOTE XXX : Modified version where we take the module version of the key
	// AS IS for the private key
	// Reason: abstract.Secret is already modulo, can't expand it again.
	privKey1Modulo := Modulo(suite, priKey1)
	privKey2Modulo := Modulo(suite, priKey2)
	pubKey1 := Ed25519PrivateToPublic(suite, privKey1Modulo)
	pubKey2 := Ed25519PrivateToPublic(suite, privKey2Modulo)
	// Extend the privKey for giving it to ed25519
	var privKey1ModuloExtended = ReducedScalarToExtended(privKey1Modulo, pubKey1)
	var privKey2ModuloExtended = ReducedScalarToExtended(privKey2Modulo, pubKey2)

	pubKeys := []ed25519.PublicKey{pubKey1, pubKey2}
	// get the equivalent to abstract.Secret
	priKey1Int := SliceToInt(suite, privKey1Modulo)
	priKey2Int := SliceToInt(suite, privKey2Modulo)

	fmt.Println("\n---------------- Sign Ed25519 -----------------\n")
	sigEd25519 := SignEd25519(msg, pubKeys, privKey1ModuloExtended, privKey2ModuloExtended)

	fmt.Println("\n---------------- Sign Abstract ----------------\n")
	// get the key into abstract.Secret/Point form
	abPubKey1 := GeEd255192Abstract(suite, pubKey1)
	abPubKey2 := GeEd255192Abstract(suite, pubKey2)
	aggPublic := suite.Point().Add(abPubKey1, abPubKey2)
	abPubKeys := []abstract.Point{abPubKey1, abPubKey2}

	sigAbstract, aggCommit := SignAbstract(suite, msg, abPubKeys, priKey1Int, priKey2Int)

	fmt.Println("\n\n------------------- 1- Verify Ed25519 Sig -----------\n")
	b := cosi.Verify(pubKeys, nil, msg, sigEd25519)
	fmt.Println(" => valid ? ", b)
	fmt.Println("\n------------------- 1- Verify Abstract Sig -----------\n")
	b = cosi.Verify(pubKeys, nil, msg, sigAbstract)
	fmt.Println(" => valid ? ", b)
	fmt.Println("\n------------------- 2- Verify Abstract --------------\n")
	b = VerifyAbstract(suite, aggPublic, aggCommit, msg, sigAbstract)
	fmt.Println(" => valid ? ", b)

}

func VerifyAbstract(suite abstract.Suite, aggPublic, aggCommit abstract.Point, msg, sig []byte) bool {
	aggR := sig[:32]
	sigS := sig[32:64]
	hash := sha512.New()
	aggPublicMarshal, _ := aggPublic.MarshalBinary()
	aggCommitMarshal, _ := aggCommit.MarshalBinary()
	if !bytes.Equal(aggR, aggCommitMarshal) {
		panic("Aie !?")
	}
	hash.Write(aggCommitMarshal)
	hash.Write(aggPublicMarshal)
	hash.Write(msg)
	k := hash.Sum(nil)
	kReduced := Modulo(suite, k)
	// k * -aggPublic + s * B = k*-A + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	// <=> s*B + k*-A = r*B
	kReducedInt := SliceToInt(suite, kReduced)
	minusPublic := suite.Point().Neg(aggPublic)
	kA := suite.Point().Mul(minusPublic, kReducedInt)
	sigSInt := SliceToInt(suite, sigS)
	sigSB := suite.Point().Mul(nil, sigSInt)

	checkR := suite.Point().Add(sigSB, kA)
	checkRMarshal, _ := checkR.MarshalBinary()

	fmt.Println("Abstract Verify AggCommit = ", Abstract2Hex(aggCommit))
	fmt.Println("Abstract Verify AggPublic = ", Abstract2Hex(aggPublic))
	fmt.Println("Abstract Verify -(AggPublic) = ", Abstract2Hex(minusPublic))
	fmt.Println("Abstract Verify Message = ", hex.EncodeToString(msg))
	fmt.Println("Abstract Verify k = ", Abstract2Hex(kReducedInt))
	fmt.Println("Abstract Verify sig(S) = ", hex.EncodeToString(sigS))
	fmt.Println("Abstract Verify sig(R) = ", hex.EncodeToString(aggR))
	fmt.Println("Abstract Verify checkR = ", Abstract2Hex(checkR))

	return bytes.Equal(checkRMarshal, aggR)
}

// return signature and aggregate commit (R)
func SignAbstract(suite abstract.Suite, msg []byte, pubKeys []abstract.Point, priKey1, priKey2 abstract.Secret) ([]byte, abstract.Point) {

	fmt.Println("Abstract SIGN HIJACK PrivKey1 = ", Abstract2Hex(priKey1))

	commit1, secret1, err := CommitAbstract(suite, bytes.NewReader(SEED1))
	if err != nil {
		panic(err)
	}
	commit2, secret2, err := CommitAbstract(suite, bytes.NewReader(SEED2))
	if err != nil {
		panic(err)
	}
	aggPublicKey := aggregatePublicKey(suite, pubKeys)
	negAggPublicKey := suite.Point().Neg(aggPublicKey)
	fmt.Println("\n HIJACK MINUS AGGPUBLIC = ", Abstract2Hex(negAggPublicKey), "\n")
	aggCommit := aggregatePublicKey(suite, []abstract.Point{commit1, commit2})

	fmt.Println("----------- Cosign Abstract 1 ------------")
	sigPart1 := CosignAbstract(suite, priKey1, secret1, msg, aggPublicKey, aggCommit)
	fmt.Println("----------- Cosign Abstract 2 ------------")
	sigPart2 := CosignAbstract(suite, priKey2, secret2, msg, aggPublicKey, aggCommit)
	if sigPart1 == nil || sigPart2 == nil {
		panic("aie")
	}
	fmt.Println("----------- Aggregate Abstract -----------")
	sigParts := []abstract.Secret{sigPart1, sigPart2}
	/* fmt.Println("Abstract Sign Secret1 = ", Abstract2Hex(secret1))*/
	//fmt.Println("Abstract Sign Commit1 = ", Abstract2Hex(commit1))
	//fmt.Println("Abstract Sign Secret2 = ", Abstract2Hex(secret2))
	//fmt.Println("Abstract Sign Commit2 = ", Abstract2Hex(commit2))

	fmt.Println("Abstract Sign AggPublic = ", Abstract2Hex(aggPublicKey))
	fmt.Println("Abstract Sign AggCommit = ", Abstract2Hex(aggCommit))
	sig := AggregateSignatureAbstract(suite, aggCommit, sigParts)
	return sig, aggCommit
}

func AggregateSignatureAbstract(suite abstract.Suite, aggCommit abstract.Point, sigParts []abstract.Secret) []byte {
	agg := suite.Secret().Zero()
	for _, s := range sigParts {
		//fmt.Printf("\tAbstract Sign AggSig(%d) : %s\n", i, Abstract2Hex(s))
		agg = agg.Add(agg, s)
	}

	fmt.Println("Abstract Sign AggSig = ", Abstract2Hex(agg))
	// no mask for the moment
	sig := agg.(*nist.Int).LittleEndian(32, 32)
	// R || S
	comm, _ := aggCommit.MarshalBinary()
	final := make([]byte, ed25519.SignatureSize)
	copy(final[:], comm)
	copy(final[32:64], sig)
	return final
}

func CosignAbstract(suite abstract.Suite, privKey, secret abstract.Secret, msg []byte, aggPublic, aggCommit abstract.Point) abstract.Secret {
	// hash the private key
	hash := sha512.New()
	privKeyBuff := privKey.(*nist.Int).LittleEndian(32, 32)
	hash.Write(privKeyBuff)
	h := hash.Sum(nil)

	// split it up
	expandedPrivKey := h[0:32]
	expandedPrivKey[0] &= 248
	expandedPrivKey[31] &= 127
	expandedPrivKey[31] |= 64
	expandedPrivKeyInt := SliceToInt(suite, expandedPrivKey)

	aggCommitMarshal, _ := aggCommit.MarshalBinary()
	aggPublicMarshal, _ := aggPublic.MarshalBinary()

	// compute k = H(R || A ]| M)
	hash.Reset()
	hash.Write(aggCommitMarshal)
	hash.Write(aggPublicMarshal)
	hash.Write(msg)
	var k [64]byte
	hash.Sum(k[:0])
	kSec := SliceToInt(suite, k[:])

	kSecReduced := kSec.LittleEndian(32, 32)
	var s = suite.Secret().(*nist.Int)
	s = s.Mul(kSec, expandedPrivKeyInt).(*nist.Int)
	s = s.Add(s, secret).(*nist.Int)

	fmt.Println("Abstract Sign k.reduced = ", hex.EncodeToString(kSecReduced))
	fmt.Println("Abstract Sign AggCommit = ", hex.EncodeToString(aggCommitMarshal))
	fmt.Println("Abstract Sign AggPublic = ", hex.EncodeToString(aggPublicMarshal))
	fmt.Println("Abstract Sign Message = ", hex.EncodeToString(msg))
	fmt.Println("Abstract Sign PrivateKeyBuff = ", hex.EncodeToString(privKeyBuff))
	fmt.Println("Abstract Sign ExpandedRaw = ", hex.EncodeToString(expandedPrivKey))
	fmt.Println("Abstract Sign ExpandedInt = ", Abstract2Hex(expandedPrivKeyInt))
	fmt.Println("Abstract Sign Secret = ", Abstract2Hex(secret))
	fmt.Println("Abstract Sign s = ", Abstract2Hex(s))
	return s
}

func aggregatePublicKey(suite abstract.Suite, pubKeys []abstract.Point) abstract.Point {
	agg := suite.Point().Null()
	for _, p := range pubKeys {
		agg = agg.Add(agg, p)
	}
	return agg
}

func CommitAbstract(suite abstract.Suite, rand io.Reader) (abstract.Point, abstract.Secret, error) {
	var secretFull [64]byte
	_, err := io.ReadFull(rand, secretFull[:])
	if err != nil {
		return nil, nil, err
	}
	secret := SliceToInt(suite, secretFull[:])
	public := suite.Point().Mul(nil, secret)
	return public, secret, nil
}

// Helper function to implement a bare-bones cosigning process.
// In practice the two cosigners would be on different machines
// ideally managed by independent badministrators or key-holders.
func SignEd25519(message []byte, pubKeys []ed25519.PublicKey,
	priKey1, priKey2 ed25519.PrivateKey) []byte {

	// Each cosigner first needs to produce a per-message commit.
	commit1, secret1, _ := cosi.Commit(bytes.NewReader(SEED1))
	commit2, secret2, _ := cosi.Commit(bytes.NewReader(SEED2))
	commits := []cosi.Commitment{commit1, commit2}
	/* fmt.Println("Ed25519 Sign Secret1 = ", hex.EncodeToString(secret1.Reduced()))*/
	//fmt.Println("Ed25519 Sign Commit1 = ", hex.EncodeToString(commit1))
	//fmt.Println("Ed25519 Sign Secret2 = ", hex.EncodeToString(secret2.Reduced()))
	//fmt.Println("Ed25519 Sign Commit2 = ", hex.EncodeToString(commit2))

	// The leader then combines these into msg an aggregate commit.
	cosigners := cosi.NewCosigners(pubKeys, nil)
	aggregatePublicKey := cosigners.AggregatePublicKey()
	aggregateCommit := cosigners.AggregateCommit(commits)
	// The cosigners now produce their parts of the collective signature.
	fmt.Println("------------------ Cosign Ed25519 1 ------------")
	sigPart1 := cosi.Cosign(priKey1, secret1, message, aggregatePublicKey, aggregateCommit)
	fmt.Println("------------------ Cosign Ed25519 2 ------------")
	sigPart2 := cosi.Cosign(priKey2, secret2, message, aggregatePublicKey, aggregateCommit)
	sigParts := []cosi.SignaturePart{sigPart1, sigPart2}
	fmt.Println("------------------ Aggregate Ed25519 -------------")
	fmt.Println("Ed25519 Sign Aggregate = ", hex.EncodeToString(aggregatePublicKey))
	fmt.Println("Ed25519 Sign AggCommit = ", hex.EncodeToString(aggregateCommit))

	// Finally, the leader combines the two signature parts
	// into a final collective signature.
	sig := cosigners.AggregateSignature(aggregateCommit, sigParts)

	return sig
}
func eddsa() {

	suite := cryptoEd.NewAES128SHA256Ed25519(false)
	msg := []byte("Hello World")

	kp1 := config.NewKeyPair(suite)
	priv1, err := kp1.Secret.MarshalBinary()
	if err != nil {
		panic("Err marshal priv1")
	}
	pub1, err := kp1.Public.MarshalBinary()
	if err != nil {
		panic("Err marshal pub1")
	}
	priv1Extended := append(priv1, pub1...)

	sig := signWithAbstract(suite, kp1.Secret, msg)
	fmt.Println("Abstract.Sig = ", hex.EncodeToString(sig[:]))

	fmt.Println("\n")
	sigGolang := ed25519.Sign(priv1Extended, msg)
	fmt.Println("Ed25519.Sig = ", hex.EncodeToString(sigGolang))

	fmt.Println("Valid ? => ", ed25519.Verify(pub1, msg, sigGolang))
	fmt.Println("\n\n\n")
}

// prime modulus of underlying field = 2^255 - 19
var prime, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

// prime order of base point = 2^252 + 27742317777372353535851937790883648493
var primeOrder, _ = new(nist.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", "", 10)

// let's try to sign something using abstract vs ed25519.Sign
// following RFC
// https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-01#section-5.1.6
func signWithAbstract(suite abstract.Suite, sec abstract.Secret, message []byte) [64]byte {
	// first hash the private key
	hash := sha512.New()
	secMarshalled, _ := sec.MarshalBinary()
	hash.Write(secMarshalled)
	h := hash.Sum(nil)

	// split up
	expandedSecretKey := h[0:32]
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 127
	expandedSecretKey[31] |= 64
	expandedSecretKeyInt := SliceToInt(suite, expandedSecretKey)
	// edwards25519 points are correct so we can use them
	// NOTE it's the original private key we take here
	publicKey := suite.Point().Mul(nil, sec)
	publicKeyMarshal, _ := publicKey.MarshalBinary()

	prefix := h[32:]
	// compute r
	hash.Reset()
	hash.Write(prefix)
	hash.Write(message)
	r := hash.Sum(nil)

	// reduce r
	rSec := SliceToInt(suite, r)
	// and the associated public key
	rPub := suite.Point().Mul(nil, rSec)
	rPubMarshal, _ := rPub.MarshalBinary()

	// compute k = H(R || A ]| M)
	hash.Reset()
	hash.Write(rPubMarshal)
	hash.Write(publicKeyMarshal)
	hash.Write(message)
	var k [64]byte
	hash.Sum(k[:0])
	kSec := SliceToInt(suite, k[:])
	//kSecReduced := kSec.LittleEndian(32, 32)

	//compute s = r + k * a
	var s = suite.Secret().(*nist.Int)
	s = s.Mul(kSec, expandedSecretKeyInt).(*nist.Int)
	s = s.Add(s, rSec).(*nist.Int)

	sMarshal := s.LittleEndian(32, 32)

	var sig [64]byte
	copy(sig[0:32], rPubMarshal)
	copy(sig[32:64], sMarshal)

	return sig
}
