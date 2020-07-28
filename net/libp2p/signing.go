package libp2p

import (
	"fmt"

	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	pb "github.com/polynetwork/mpcd/net/protos"
)

const signPrefix = "mpcd-unicast:"

func signMessage(
	message *pb.UnicastNetworkMessage,
	privKey libp2pcrypto.PrivKey) error {

	messageCopy := message
	messageCopy.Signature = nil

	bytes, err := messageCopy.Marshal()
	if err != nil {
		return err
	}
	bytes = withSignPrefix(bytes)

	signature, err := privKey.Sign(bytes)
	if err != nil {
		return err
	}
	message.Signature = signature

	return nil
}

func verifyMessageSignature(
	message *pb.UnicastNetworkMessage,
	pubKey libp2pcrypto.PubKey,
) error {

	messageCopy := message
	signature := message.Signature
	messageCopy.Signature = nil

	bytes, err := messageCopy.Marshal()
	if err != nil {
		return err
	}
	bytes = withSignPrefix(bytes)

	valid, err := pubKey.Verify(bytes, signature)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid message signature")
	}

	return nil
}

func withSignPrefix(bytes []byte) []byte {
	return append([]byte(signPrefix), bytes...)
}
