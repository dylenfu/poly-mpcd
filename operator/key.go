package operator

import (
	"fmt"
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/accounts/keystore"
)

// PrivateKey represents peer's static key associated with an on-chain stake.
// it is used to authenticate the peer and for attributability(signing).
// todo(fuk): modify comment stake
type PrivateKey = ecdsa.PrivateKey

// PublicKey represents peer's static key associated with an on-chain statke.
// it is used to authenticate the peer and for attributability(verification).
// todo(fuk): modify comment stake
type PublicKey = ecdsa.PublicKey

// GenerateKeyPair generates a new, random static key based on secp256k1 ethereum curve
// todo(fuk): use dna keypair
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	ecdsaKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return (*PrivateKey)(ecdsaKey), (*PublicKey)(&ecdsaKey.PublicKey), nil
}

// EthereumKeyToOperatorKey transforms a `go-ethereum` based ecdsa key into the
// format supported by all packages used in mpcd
// todo(fuk): use dna keypair
func EthereumKeyToOperatorKey(ethereumKey *keystore.Key) (*PrivateKey, *PublicKey) {
	privKey := ethereumKey.PrivateKey
	return (*PrivateKey)(privKey), (*PublicKey)(&privKey.PublicKey)
}

// Marshal take an operator's public key and produces uncompressed public key 
// as a slice of bytes
func Marshal(publickKey *PublicKey) []byte {
	return elliptic.Marshal(publickKey.Curve, publickKey.X, publickKey.Y)
}

// Unmarshal take raw bytes and produces an uncompressed, operator's public key.
// unmarshal assume the publicKey's curve type of S256 as defined in geth
func Unmarshal(data []byte) (*PublicKey, error) {
	x, y := elliptic.Unmarshal(crypto.S256(), data)
	if x == nil {
		return nil, fmt.Errorf("incorrect public key bytes")
	}
	ecdsaPublicKey := &ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}
	return (*PublicKey)(ecdsaPublicKey), nil
}