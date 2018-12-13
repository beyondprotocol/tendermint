package secp256r1

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	amino "github.com/tendermint/go-amino"
	"golang.org/x/crypto/ripemd160" // forked to github.com/tendermint/crypto

	"github.com/tendermint/tendermint/crypto"
)

const (
	//Amino route for deepcover public key
	PubKeyAminoRoute = "deepcover/PubKeySecp256r1"
)

var cdc = amino.NewCodec()

func init() {
	cdc.RegisterConcrete(PubKeySecp256r1{},
		PubKeyAminoRoute, nil)
}

//-------------------------------------

var _ crypto.PubKey = PubKeySecp256r1{}

// PubKeySecp256r1Size is comprised of 32 bytes for one field element
// (the x-coordinate), plus one byte for the parity of the y-coordinate.
const PubKeySecp256r1Size = 65

// PubKeySecp256r1 implements crypto.PubKey.
// It is the compressed form of the pubkey. The first byte depends is a 0x02 byte
// if the y-coordinate is the lexicographically largest of the two associated with
// the x-coordinate. Otherwise the first byte is a 0x03.
// This prefix is followed with the x-coordinate.
type PubKeySecp256r1 [PubKeySecp256r1Size]byte

// Address returns a Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKeySecp256r1) Address() crypto.Address {
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(pubKey[:]) // does not error
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha) // does not error
	return crypto.Address(hasherRIPEMD160.Sum(nil))
}

// Bytes returns the pubkey marshalled with amino encoding.
func (pubKey PubKeySecp256r1) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

func (pubKey PubKeySecp256r1) VerifyBytes(msg []byte, sig []byte) bool {
	pub := new(ecdsa.PublicKey)
	x := new(big.Int)
	x.SetBytes(pubKey[:32])
	pub.X = x
	y := new(big.Int)
	y.SetBytes(pubKey[32:])
	pub.Y = y
	pub.Curve = elliptic.P256()
	return VerifySignature(pub, msg, hex.EncodeToString(sig[:32]), hex.EncodeToString(sig[32:]))
}

func (pubKey PubKeySecp256r1) String() string {
	return fmt.Sprintf("PubKeySecp256r1{%X}", pubKey[:])
}

func (pubKey PubKeySecp256r1) Equals(other crypto.PubKey) bool {
	if otherSecp, ok := other.(PubKeySecp256r1); ok {
		return bytes.Equal(pubKey[:], otherSecp[:])
	}
	return false
}

// VerifySignature verifies the signature using public keys and calculated digest
func VerifySignature(pub *ecdsa.PublicKey, digest []byte, signatureR string, signatureS string) bool {
	r := new(big.Int)
	s := new(big.Int)
	r.SetString(signatureR, 16)
	s.SetString(signatureS, 16)
	return ecdsa.Verify(pub, digest, r, s)
}
