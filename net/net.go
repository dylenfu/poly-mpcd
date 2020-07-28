package net

import (
	"crypto/ecdsa"

	"github.com/gogo/protobuf/proto"
	"github.com/polynetwork/mpcd/net/key"
)

// TransportIdentifier represents a protocol-level identify, it is an opacha type to network layer
type TransportIdentifier interface {
	String() string
}

// Message represents a message exchanged within the network layer. it carries a sender
// id for transport layer, and if available, for network layer. it also carries an unmashlled payload.
type Message interface {
	TransportSenderID() TransportIdentifier
	SenderPublicKey() []byte

	Payload() interface{}

	Type() string
	Seqno() uint64
}

// TaggedMarshaler is an interface that includes proto's marshaler.
// but also provides a string type for the marshalable object.
type TaggedMarshaler interface {
	proto.Marshaler
	Type() string
}

// TaggedUnmarshaler is an interface that includes the proto.Unmarshaler
// interface, but also provides a string type for the unmarshalable object. The
// Type() method is expected to be invokable on a just-initialized instance of
// the unmarshaler (i.e., before unmarshaling is completed).
type TaggedUnmarshaler interface {
	proto.Unmarshaler
	Type() string
}

type Provider interface {
}

// ConnectionManager is an interface which exposes peers a client is connected to,
// and their identities, so that a client may forcibly disconnect from any given connected peer.
type ConnectionManager interface {
	ConnectedPeers() []string
	GetPublicKey(connectedPeer string) (*key.NetworkPublic, error)
	DisconnectPeer(connectedPeer string)

	// AddrStrings returns all listen addresses of the provider.
	AddrStrings() []string
	IsConnected(address string) bool
}

// Firewall represents a set of rules that remote peer has to conform so that
// a connect with that peer can be approved
type Firewall interface {

	// Validate takes the remote public key and executes all the checks
	// needed to decide whether the connection with the peer can be approved.
	// If expectations are not met, this function should return an error
	// describe what is wrong
	Validate(remotePublicKey *ecdsa.PublicKey) error
}
