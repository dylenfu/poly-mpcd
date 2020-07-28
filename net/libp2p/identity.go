package libp2p

import (
	"fmt"

	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	peer "github.com/libp2p/go-libp2p-core/peer"
	pb "github.com/polynetwork/mpcd/net/protos"
)

// identity represents a group of member's network level identity. it
// implements the net.TransportIdentifier interface. a valid group member
// will generate or provide a keypair, which will correspond to a network ID.
//
// consumers of the net package require an ID to register with protocol level
// IDs, as well as public key for authentication.
type identity struct {
	id      peer.ID
	pubKey  libp2pcrypto.PubKey
	privKey libp2pcrypto.PrivKey
}

func createIdentity(privateKey libp2pcrypto.PrivKey) (*identity, error) {
	peerID, err := peer.IDFromPublicKey(privateKey.GetPublic())
	if err != nil {
		return nil, fmt.Errorf("could not transform private key to identity: [%v]", err)
	}

	return &identity{id: peerID, pubKey: privateKey.GetPublic(), privKey: privateKey}, nil
}

func (i *identity) Marshal() ([]byte, error) {
	var (
		err         error
		pubkeyBytes []byte
		pubKey      = i.pubKey
	)

	if pubKey == nil {
		if pubKey, err = i.id.ExtractPublicKey(); err != nil {
			return nil, err
		}
	}
	if pubkeyBytes, err = pubKey.Bytes(); err != nil {
		return nil, err
	}
	return (&pb.Identity{Pubkey: pubkeyBytes}).Marshal()
}

func (i *identity) Unmarshal(data []byte) error {
	var (
		err        error
		pid        peer.ID
		pbIdentity pb.Identity
	)

	if err = pbIdentity.Unmarshal(data); err != nil {
		return fmt.Errorf("unmarshalling failed: [%v]", err)
	}
	if i.pubKey, err = libp2pcrypto.UnmarshalPublicKey(pbIdentity.Pubkey); err != nil {
		return err
	}
	if pid, err = peer.IDFromPublicKey(i.pubKey); err != nil {
		return fmt.Errorf("failed to generate valid libp2p identity: [%v]", err)
	}
	i.id = pid
	return nil
}

type networkIdentity peer.ID

func (ni networkIdentity) String() string {
	return peer.ID(ni).String()
}
