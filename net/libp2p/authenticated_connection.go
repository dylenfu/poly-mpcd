package libp2p

import (
	"encoding/hex"
	"fmt"
	"net"

	protoio "github.com/gogo/protobuf/io"
	libp2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	cusnet "github.com/polynetwork/mpcd/net"
	"github.com/polynetwork/mpcd/net/handshake"
	"github.com/polynetwork/mpcd/net/key"
	pb "github.com/polynetwork/mpcd/protos/net"
)

// enough space for a proto-encoded evnvelope with a message, peer ID, and sig.
const maxFrameSize = 1 << 10

// authenticatedConnection turns inbound and outbound unauthenticated,
// plain-text connections to authenticated, plain-text connections.
// noticeably, it does not guarantee confidentiality as it does not
// encrypt connections.
type authenticatedConnection struct {
	net.Conn

	localPeerID         peer.ID
	localPeerPrivateKey libp2pcrypto.PrivKey

	remotePeerID        peer.ID
	remotePeerPublicKey libp2pcrypto.PubKey

	firewall cusnet.Firewall

	protocol string
}

// newAuthenticatedInboundConnection is the connection that's formed by
// transport.SecureInbound. this function is executed by the receiver of a new
// connection, who acts as the responder. this side of the connection lacks
// knowledge of the remotePeerID (passed in as empty string). on success running
// the responder side of the handshake, it returns a fully-authenticated
// connection, which grants access to the network
func newAuthenticatedInboundConnection(
	unauthenticatedConnection net.Conn,
	localPeerID peer.ID,
	privateKey libp2pcrypto.PrivKey,
	firewall cusnet.Firewall,
	protocol string,
) (*authenticatedConnection, error) {

	ac := &authenticatedConnection{
		Conn:                unauthenticatedConnection,
		localPeerID:         localPeerID,
		localPeerPrivateKey: privateKey,
		firewall:            firewall,
		protocol:            protocol,
	}

	if err := ac.runHandshakeAsResponder(); err != nil {
		// close the connection before returning (if it hasn't already)
		// otherwise we leak
		ac.Close()
		return nil, fmt.Errorf("connection handshake failed: [%v]", err)
	}

	if err := ac.checkFirewallRules(); err != nil {
		ac.Close()
		return nil, fmt.Errorf("connection handshake failed: [%v]", err)
	}
	return ac, nil
}

// newAuthenticatedOutboundConnection is the connection that's formed by
// transport.SecureOutbound. this function is executed by the initiator of a new
// connection. this side of the connection has knowledge of the remote peer
// identity. on success running the initiator side of the handshake, it returns a
// fully-authenticated connection, which grants access to the network
func newAuthenticatedOutboundConnection(
	unauthenticatedConn net.Conn,
	localPeerID peer.ID,
	privateKey libp2pcrypto.PrivKey,
	remotePeerID peer.ID,
	firewall cusnet.Firewall,
	protocol string,
) (*authenticatedConnection, error) {

	remotePublicKey, err := remotePeerID.ExtractPublicKey()
	if err != nil {
		return nil, fmt.Errorf("could not create new authenticated outbound connection: [%v]", err)
	}

	ac := &authenticatedConnection{
		Conn:                unauthenticatedConn,
		localPeerID:         localPeerID,
		localPeerPrivateKey: privateKey,
		remotePeerID:        remotePeerID,
		remotePeerPublicKey: remotePublicKey,
		firewall:            firewall,
		protocol:            protocol,
	}

	if err := ac.runHandshakeAsInitiator(); err != nil {
		ac.Close()
		return nil, fmt.Errorf("connection handshake failed: [%v]", err)
	}

	if err := ac.checkFirewallRules(); err != nil {
		ac.Close()
		return nil, fmt.Errorf("connection handshake failed: [%v]", err)
	}

	return ac, nil
}

func (ac *authenticatedConnection) checkFirewallRules() error {
	networkKey, ok := ac.remotePeerPublicKey.(*key.NetworkPublic)
	if !ok {
		return fmt.Errorf("unexpected type of remote peer's public key")
	}

	return ac.firewall.Validate(key.NetworkKeyToECDSAKey(networkKey))
}

// runHandshakeAsInitiator
func (ac *authenticatedConnection) runHandshakeAsInitiator() error {
	// initiator station
	initiatorConnectionReader := protoio.NewDelimitedReader(ac.Conn, maxFrameSize)
	initiatorConnectionWriter := protoio.NewDelimitedWriter(ac.Conn)

	// act1
	initiatorAct1, err := handshake.InitiateHandshake(ac.protocol)
	if err != nil {
		return err
	}
	act1WireMessage, err := initiatorAct1.Message().Marshal()
	if err != nil {
		return err
	}
	if err := ac.initiatorSendAct1(act1WireMessage, initiatorConnectionWriter); err != nil {
		return err
	}

	initiatorAct2 := initiatorAct1.Next()

	// act2
	act2Message, err := ac.initiatorReceiveAct2(initiatorConnectionReader)
	if err != nil {
		return err
	}

	initiatorAct3, err := initiatorAct2.Next(act2Message)
	if err != nil {
		return err
	}

	// act3
	act3WireMessage, err := initiatorAct3.Message().Marshal()
	if err != nil {
		return err
	}
	if err := ac.initiatorSendAct3(act3WireMessage, initiatorConnectionWriter); err != nil {
		return err
	}

	return nil
}

func (ac *authenticatedConnection) runHandshakeAsResponder() error {
	// responder station

	responderConnectionReader := protoio.NewDelimitedReader(ac.Conn, maxFrameSize)
	responderConnectionWriter := protoio.NewDelimitedWriter(ac.Conn)

	// act1
	act1Message, err := ac.responderReceiveAct1(responderConnectionReader)
	if err != nil {
		return err
	}
	responderAct2, err := handshake.AnswerHandshake(act1Message, ac.protocol)
	if err != nil {
		return err
	}

	// act2
	act2WireMessage, err := responderAct2.Message().Marshal()
	if err != nil {
		return err
	}
	if err := ac.responderSendAct2(act2WireMessage, responderConnectionWriter); err != nil {
		return err
	}

	responderAct3 := responderAct2.Next()

	// act3
	act3Message, err := ac.responderReceiveAct3(responderConnectionReader)
	if err != nil {
		return err
	}
	if err := responderAct3.FinalizeHandshake(act3Message); err != nil {
		return err
	}

	return nil
}

// initiatorSendAct1 signs a marshaled *handshake.Act1Message, prepares
// the message in a pb.HandshakeEnvelop, and send the message to the responder
// (over the open connection) from the initiator.
func (ac *authenticatedConnection) initiatorSendAct1(
	act1WireMessage []byte,
	initiatorConnectionWriter protoio.Writer) error {

	signedAct1Message, err := ac.localPeerPrivateKey.Sign(act1WireMessage)
	if err != nil {
		return err
	}

	act1Envelop1 := &pb.HandshakeEnvelope{
		Message:   act1WireMessage,
		Signature: signedAct1Message,
		PeerID:    []byte(ac.localPeerID),
	}

	if err := initiatorConnectionWriter.WriteMsg(act1Envelop1); err != nil {
		return err
	}

	return nil
}

// initiatorReceiveAct2 unmarshal a pb.HandshakeEnvelope from a responder,
// verifies that the signed message matches the expected peer.ID, and returns
// the handshake.Act2Message for processing by the initiator.
func (ac *authenticatedConnection) initiatorReceiveAct2(
	initiatorConnectionReader protoio.ReadCloser,
) (*handshake.Act2Message, error) {

	var (
		act2Envelope pb.HandshakeEnvelope
		act2Message  = &handshake.Act2Message{}
	)

	if err := initiatorConnectionReader.ReadMsg(&act2Envelope); err != nil {
		return nil, err
	}

	if err := ac.verify(
		ac.remotePeerID,
		peer.ID(act2Envelope.GetPeerID()),
		act2Envelope.GetMessage(),
		act2Envelope.GetSignature(),
	); err != nil {
		return nil, err
	}

	if err := act2Message.Unmarshal(act2Envelope.Message); err != nil {
		return nil, err
	}

	return act2Message, nil
}

// initiatorSendAct3 signs a marshaled *handshake.Act3Message, prepares the
// message in a pb.handshakeEnvelope, and sends the message to the responder
// (over the open connection) from the initiator.
func (ac *authenticatedConnection) initiatorSendAct3(
	act3WireMessage []byte,
	initiatorConnectionWriter protoio.WriteCloser) error {

	signedAct3Message, err := ac.localPeerPrivateKey.Sign(act3WireMessage)
	if err != nil {
		return err
	}

	act3Envelop := &pb.HandshakeEnvelope{
		Message:   act3WireMessage,
		PeerID:    []byte(ac.localPeerID),
		Signature: signedAct3Message,
	}

	if err := initiatorConnectionWriter.WriteMsg(act3Envelop); err != nil {
		return err
	}

	return nil
}

// responderReceiveAct1 unmarshal a pb.HandshakeEnvelope from an initiator,
// verifies that the signed messages matches by the expected peer.ID, and returns
// the handshake.Act1Message for processing by the responder.
func (ac *authenticatedConnection) responderReceiveAct1(
	responderConnectionReader protoio.ReadCloser,
) (*handshake.Act1Message, error) {

	var (
		act1Envelope pb.HandshakeEnvelope
		act1Message  = &handshake.Act1Message{}
	)

	if err := responderConnectionReader.ReadMsg(&act1Envelope); err != nil {
		return nil, err
	}

	// in libp2p, the responder doesn't know the identity of the initiator
	// during the handshake, we overcome this limitation by sending the identity
	// and public key in the envelop. in the first act of handshake, the
	// responder extracts this information
	ac.remotePeerID = peer.ID(act1Envelope.GetPeerID())
	remotePublicKey, err := ac.remotePeerID.ExtractPublicKey()
	if err != nil {
		return nil, err
	}
	ac.remotePeerPublicKey = remotePublicKey

	if err := ac.verify(
		ac.remotePeerID,
		peer.ID(act1Envelope.GetPeerID()),
		act1Envelope.GetMessage(),
		act1Envelope.GetSignature()); err != nil {
		return nil, err
	}

	if err := act1Message.Unmarshal(act1Envelope.Message); err != nil {
		return nil, err
	}

	return act1Message, nil
}

// responderSendAct2 signs a marshaled *handshake.Act2Message, prepares
// the message in a pb.HandshakeEnvelope, and sends the message to the
// initiator(over the open connection) from the responder.
func (ac *authenticatedConnection) responderSendAct2(
	act2WireMessage []byte,
	responderConnectionWriter protoio.WriteCloser,
) error {

	signedAct2Message, err := ac.localPeerPrivateKey.Sign(act2WireMessage)
	if err != nil {
		return err
	}

	act2Envelope := &pb.HandshakeEnvelope{
		Message:   act2WireMessage,
		PeerID:    []byte(ac.localPeerID),
		Signature: signedAct2Message,
	}

	if err := responderConnectionWriter.WriteMsg(act2Envelope); err != nil {
		return err
	}

	return nil
}

// responderReceiveAct3 unmarshal a pb.Handshake from an initiator,
// verifies that the signed messages matches the expected peer.ID, and returns
// the handshake.Act3Message for processing by the responder.
func (ac *authenticatedConnection) responderReceiveAct3(
	responderConnectionReader protoio.ReadCloser,
) (*handshake.Act3Message, error) {

	var (
		act3Envelope pb.HandshakeEnvelope
		act3Message  = &handshake.Act3Message{}
	)

	if err := responderConnectionReader.ReadMsg(&act3Envelope); err != nil {
		return nil, err
	}

	if err := ac.verify(
		ac.remotePeerID,
		peer.ID(act3Envelope.GetPeerID()),
		act3Envelope.GetMessage(),
		act3Envelope.GetSignature(),
	); err != nil {
		return nil, err
	}

	if err := act3Message.Unmarshal(act3Envelope.Message); err != nil {
		return nil, err
	}
	return act3Message, nil
}

// verify checks if the pinned(expected) identity matches the message
// sender's identity before running through signature verification check.
func (ac *authenticatedConnection) verify(
	expectedSender, actualSender peer.ID,
	messageBytes, signatureBytes []byte) error {

	if expectedSender != actualSender {
		return fmt.Errorf("pinned identity [%v] doesn't matach sender identity [%v]",
			expectedSender, actualSender)
	}

	pubKey, err := actualSender.ExtractPublicKey()
	if err != nil {
		return fmt.Errorf("failed to extract pubkey from peer [%v]", actualSender)
	}

	ok, err := pubKey.Verify(messageBytes, signatureBytes)
	if err != nil {
		return fmt.Errorf("failed to verify signature [0x%v] for sender [%v]: [%v]",
			hex.EncodeToString(signatureBytes), actualSender.Pretty(), err)
	}

	if !ok {
		return fmt.Errorf("invalid signature [0x%v] on message from sender [%v]",
			hex.EncodeToString(signatureBytes), actualSender.Pretty())
	}

	return nil
}

// LocalPeer retrieves the local peer
func (ac *authenticatedConnection) LocalPeer() peer.ID {
	return ac.localPeerID
}

// LocalPrivateKey retrieves the local peer's private key
func (ac *authenticatedConnection) LocalPrivateKey() libp2pcrypto.PrivKey {
	return ac.localPeerPrivateKey
}

// RemotePeer returns the remote peer ID if we initiated the dail. other wise,
// it returns ""(because this connection isn't actually secure).
func (ac *authenticatedConnection) RemotePeer() peer.ID {
	return ac.remotePeerID
}

// RemotePublicKey retrieves the remote peer's public key
func (ac *authenticatedConnection) RemotePublicKey() libp2pcrypto.PubKey {
	return ac.remotePeerPublicKey
}
