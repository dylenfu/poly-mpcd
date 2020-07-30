package handshake

import (
	"encoding/binary"
	"fmt"

	pb "github.com/polynetwork/mpcd/protos/net"
)

const (
	nonceByteLength     = 8
	challengeByteLength = 32
)

// Marshal converts this Act1Message to a byte array suitable for network
// communication.
func (am *Act1Message) Marshal() ([]byte, error) {
	nonceBytes := make([]byte, nonceByteLength)
	binary.LittleEndian.PutUint64(nonceBytes, am.nonce1)
	return (&pb.Act1Message{Nonce: nonceBytes, Protocol: am.protocol1}).Marshal()
}

// Unmarshal converts a byte array produced by Marshal to a Act1Message.
func (am *Act1Message) Unmarshal(bytes []byte) error {
	pbAct1 := pb.Act1Message{}
	if err := pbAct1.Unmarshal(bytes); err != nil {
		return err
	}

	nonceLength := len(pbAct1.Nonce)
	if nonceLength != nonceByteLength {
		return fmt.Errorf("invalid nonce length: [%v]", nonceLength)
	}

	am.nonce1 = binary.LittleEndian.Uint64(pbAct1.Nonce)

	am.protocol1 = pbAct1.Protocol

	return nil
}

// Marshal converts this Act2Message to a byte array suitable for network
// communication.
func (am *Act2Message) Marshal() ([]byte, error) {
	nonceBytes := make([]byte, nonceByteLength)
	binary.LittleEndian.PutUint64(nonceBytes, am.nonce2)
	return (&pb.Act2Message{
		Nonce:     nonceBytes,
		Challenge: am.challenge[:],
		Protocol:  am.protocol2,
	}).Marshal()
}

// Unmarshal converts a byte array produced by Marshal to a Act2Message.
func (am *Act2Message) Unmarshal(bytes []byte) error {
	pbAct2 := pb.Act2Message{}
	if err := pbAct2.Unmarshal(bytes); err != nil {
		return err
	}

	nonceLength := len(pbAct2.Nonce)
	if nonceLength != nonceByteLength {
		return fmt.Errorf("invalid nonce length: [%v]", nonceLength)
	}

	am.nonce2 = binary.LittleEndian.Uint64(pbAct2.Nonce)

	challengeLength := len(pbAct2.Challenge)
	if challengeLength != challengeByteLength {
		return fmt.Errorf("invalid challenge length: [%v]", challengeLength)
	}

	copy(am.challenge[:], pbAct2.Challenge[:challengeByteLength])

	am.protocol2 = pbAct2.Protocol

	return nil
}

// Marshal converts this Act3Message to a byte array suitable for network
// communication.
func (am *Act3Message) Marshal() ([]byte, error) {
	return (&pb.Act3Message{Challenge: am.challenge[:]}).Marshal()
}

// Unmarshal converts a byte array produced by Marshal to a Act3Message.
func (am *Act3Message) Unmarshal(bytes []byte) error {
	pbAct3 := pb.Act3Message{}
	if err := pbAct3.Unmarshal(bytes); err != nil {
		return err
	}

	challengeLength := len(pbAct3.Challenge)
	if challengeLength != challengeByteLength {
		return fmt.Errorf("invalid challenge length: [%v]", challengeLength)
	}

	copy(am.challenge[:], pbAct3.Challenge[:challengeByteLength])

	return nil
}
