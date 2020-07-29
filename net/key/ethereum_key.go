package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/polynetwork/mpcd/operator"

	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
)

// NetworkPrivate represents peer's static key associated with an on-chain stake.
// it is used to authticate the peer and for message attributability.
// - each message leaving the peer is signed with its private network key.
type NetworkPrivate = libp2pcrypto.Secp256k1PrivateKey

// NetworkPublic represents peer's static key associated with an on-chain stake.
// it is used to authticate the peer and for message attributability.
// - each received message is validated against sender's public key.
type NetworkPublic = libp2pcrypto.Secp256k1PublicKey

// GenerateStaticNetworkKey generates a new, random static key based on
// ethereum secp256k1 curve
func GenerateStaticNetworkKey() (*NetworkPrivate, *NetworkPublic, error) {
	privKey, pubKey, err := operator.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	networkPrivateKey, networkPublicKey := OperatorKeyToNetworkKey(privKey, pubKey)
	return networkPrivateKey, networkPublicKey, nil
}

// OperatorKeyToNetworkKey transform the operator key into the format supported by
// the network layer. Because all curve parameters of secp256k1 curve defined by
// `go-ethereum` and all curve parameters of secp256k1 curve defined by `btcsuite` used
// by `libp2p` under the hood are identical, we can simply rewrite the private key
//
// `libp2p` do not recognize `go-ethereum` curves and when it comes to create peer's ID
// or deserialized the key, operation fails with unrecognize curve error. this is no longer
// a problem if we transform the key using this function.
func OperatorKeyToNetworkKey(
	operatorPrivateKey *operator.PrivateKey,
	operatorPublicKey *operator.PublicKey,
) (*NetworkPrivate, *NetworkPublic) {
	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), operatorPrivateKey.D.Bytes())
	return (*NetworkPrivate)(privKey), (*NetworkPublic)(pubKey)
}

// NetworkPubKeyToEthAddress transform network public key into ethereum account address,
// in a string format.
func NetworkPubKeyToEthAddress(publicKey *NetworkPublic) string {
	ecdsaKey := (*btcec.PublicKey)(publicKey).ToECDSA()
	return crypto.PubkeyToAddress(*ecdsaKey).String()
}

// Marshal takes a network public key, converts into an ecdsa public key.
// and use go's standard library elliptic marshal method to convert the
// public key into a slice of bytes in the correct format of the key type.
// this allows external consumers of this key to verify integrity of the key
// without to having understand the internals of the net pkg.
func Marshal(publicKey *NetworkPublic) []byte {
	ecdsaKey := (*btcec.PublicKey)(publicKey).ToECDSA()
	return elliptic.Marshal(btcec.S256(), ecdsaKey.X, ecdsaKey.Y)
}

// Libp2pKeyToNetworkKey takes an interface type, libp2pcrypto.PubKey, and
// returns the concrete type specific to this package. If it fails to do so, it
// returns nil
func Libp2pKeyToNetworkKey(publicKey libp2pcrypto.PubKey) *NetworkPublic {
	switch networkKey := publicKey.(type) {
	case *libp2pcrypto.Secp256k1PublicKey:
		return (*NetworkPublic)(networkKey)
	}
	return nil
}

func NetworkKeyToECDSAKey(publicKey *NetworkPublic) *ecdsa.PublicKey {
	return (*btcec.PublicKey)(publicKey).ToECDSA()
}
