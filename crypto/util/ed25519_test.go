package util

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bford/golang-x-crypto/ed25519"
	cryptoEd "github.com/dedis/crypto/edwards/ed25519"
)

// is ScReduce is the same as modulo ?
func TestModuloReduce(t *testing.T) {
	suite := cryptoEd.NewAES128SHA256Ed25519(false)
	// Create keypairs for the two cosigners.
	_, priKey1, _ := ed25519.GenerateKey(nil)

	privKey1Modulo := Modulo(suite, priKey1)

	t.Log("PrivKeyModulo = ", hex.EncodeToString(privKey1Modulo))

	var privKey1Reduced [32]byte
	var privKeyNorm [64]byte
	copy(privKeyNorm[:], priKey1[:])
	ScReduce(&privKey1Reduced, &privKeyNorm)

	t.Log("privKey1Reduced = ", hex.EncodeToString(privKey1Reduced[:]))
	if !bytes.Equal(privKey1Reduced[:], privKey1Modulo) {
		t.Error("Not equal")
	}
}

// Modulo to abstract == ?
func TestModuloToAbstract(t *testing.T) {
	suite := cryptoEd.NewAES128SHA256Ed25519(false)
	// Create keypairs for the two cosigners.
	_, priKey1, _ := ed25519.GenerateKey(nil)

	privKey1Modulo := Modulo(suite, priKey1)
	sec := SliceToInt(suite, privKey1Modulo)
	hexPrivModulo := hex.EncodeToString(privKey1Modulo)
	hexSec := Abstract2Hex(sec)
	t.Log("privkeyModulo = ", hexPrivModulo)
	t.Log("Sec = ", hexSec)
	if hexPrivModulo != hexSec {
		t.Error("Not equal")
	}
}

// if we extend does it stay the same for the private ?
func TestReducedToExtended(t *testing.T) {
	suite := cryptoEd.NewAES128SHA256Ed25519(false)
	// Create keypairs for the two cosigners.
	pubKey1, priKey1, _ := ed25519.GenerateKey(nil)

	privKey1Modulo := Modulo(suite, priKey1)
	privKey1Extended := ReducedScalarToExtended(privKey1Modulo, pubKey1)
	sec := SliceToInt(suite, privKey1Modulo)

	hexPrivExtended := hex.EncodeToString(privKey1Extended[:32])
	hexSec := Abstract2Hex(sec)
	t.Log("privkeyModulo = ", hexPrivExtended)
	t.Log("Sec = ", hexSec)
	if hexPrivExtended != hexSec {
		t.Error("Not equal")
	}
}

func TestEd25519SCalarToPublic(t *testing.T) {
	// Create keypairs for the two cosigners.
	pubKey1, priKey1, _ := ed25519.GenerateKey(nil)

	pubKey1Computed := Ed25519ScalarToPublic(priKey1)
	t.Log("pubKey1 = ", hex.EncodeToString(pubKey1))
	t.Log("pubKey1Computed = ", hex.EncodeToString(pubKey1Computed))
	if !bytes.Equal(pubKey1, pubKey1Computed) {
		t.Error("Not Equal")
	}

}

// Test if generating a public key from a modulo-d priKey or its equivalent secret is
// equivalent
func TestScalarToPublic(t *testing.T) {
	suite := cryptoEd.NewAES128SHA256Ed25519(false)
	// Create keypairs for the two cosigners.
	_, priKey1, _ := ed25519.GenerateKey(nil)

	// reduce the private key
	var priKeyB [64]byte
	copy(priKeyB[:], priKey1[:])
	var privKey1Modulo [32]byte
	ScReduce(&privKey1Modulo, &priKeyB)
	// and generate the public key from it
	pubKey1Modulo := Ed25519ScalarToPublic(privKey1Modulo[:])

	// convert the modulo-d private key into a nist.Int
	//sec := SliceToInt(suite, privKey1Modulo[:])
	sec := SliceToInt(suite, priKey1)
	// marshal it
	secMarshal := sec.LittleEndian(32, 32)
	// digest it and prune it
	digest := privateToDigest(secMarshal)
	// go back to a secret
	// PB secPruned != digest from Ed25519ScalarToPublic
	// So when creating a public key from:
	// Ed25519MultBase(H(Ed25519 scalar) + prune) => p1
	// Point().Mul(nil,(H(Ed25519 scalar) + prne) => p2
	// p1 != p2
	// can't get the right private / public key
	fmt.Println("\n WARNING \n")
	secPruned := SliceToInt(suite, digest[32:])
	fmt.Println("\n WARNING \n")
	// multiply by the base
	pubPoint := suite.Point().Mul(nil, secPruned)
	pubPointMarshal, _ := pubPoint.MarshalBinary()
	t.Log("Digest - Abstract: ", hex.EncodeToString(digest))
	t.Log("Digest- SecPruned: ", Abstract2Hex(secPruned))
	t.Log("Modulo - ed25519: ", hex.EncodeToString(privKey1Modulo[:]))
	t.Log("Moduloe - Abstract: ", hex.EncodeToString(secMarshal))
	t.Log("pubPoint = ", Abstract2Hex(pubPoint))
	t.Log("pubKey1Modulo = ", hex.EncodeToString(pubKey1Modulo))
	_, s1 := Ed25519ScalarToSecret(suite, priKey1)
	po1 := suite.Point().Mul(nil, s1)
	t.Log("Method = ", Abstract2Hex(po1))
	if !bytes.Equal(pubPointMarshal, pubKey1Modulo) {
		t.Error("Not equal")
	}
	/*pubSecModulo := suite.Point().Mul(nil, sec)*/
	//pubSecModuloMarshal, _ := pubSecModulo.MarshalBinary()
	//t.Log("pubKey1Modulo = ", hex.EncodeToString(pubKey1Modulo))
	//t.Log("pubSecModulo = ", hex.EncodeToString(pubSecModuloMarshal))
	//if !bytes.Equal(pubSecModuloMarshal, pubKey1Modulo) {
	//t.Error("notequal")
	/*}*/
}

func TestReducedPublic(t *testing.T) {
	// test whether generating a public key from a reduced private key or a
	// extended private key is the same
	// It should be *not* since a public key is generated from the hash of the
	// private key => different private key generate different public key
	suite := cryptoEd.NewAES128SHA256Ed25519(false)
	// Create keypairs for the two cosigners.
	pubKey1, priKey1, _ := ed25519.GenerateKey(nil)

	privKey1Modulo := Modulo(suite, priKey1)
	privKey1ModuloInt := SliceToInt(suite, privKey1Modulo)
	pubKey1Modulo := suite.Point().Mul(nil, privKey1ModuloInt)
	pubKey1ModuloMarshal, _ := pubKey1Modulo.MarshalBinary()

	t.Log("pubKey1 = ", hex.EncodeToString(pubKey1))
	t.Log("pubKey1Modulo = ", Abstract2Hex(pubKey1Modulo))
	if bytes.Equal(pubKey1ModuloMarshal, pubKey1) {
		t.Error("Not Equal")
	}
}
