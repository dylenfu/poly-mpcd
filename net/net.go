package net

import (
	"context"
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

// BroadcastChannel represents a named pubsub channel. it allows group members
// to broadcast and receive messages. BroadcastChannel implements strategy
// for the retransmission of broadcast messages and handle dumplicates before
// passing the received message to the client
type BroadcastChannel interface {
	// Name returns the name of this broadcast channel.
	Name() string

	// Send function publishes a message m to the channel. message m needs to
	// conform to the marshalling interface. Message will be periodically
	// retransmitted by the channel for the lifetime of the provided context.
	Send(ctx context.Context, m TaggedMarshaler) error

	// Recv installs a message handler that will receives messages from the
	// channel for the entire lifetime of the provided context.
	// when the context is done, handler is automatically unregistered and
	// receives no more messages. Already received message retransmissions are
	// filtered out before calling the handler
	Recv(ctx context.Context, handler func(m Message))

	// RegisterUnmarshaler registers an unmarshaler that will unmarshal a given
	// type to a concrete object that can be passed to and understood by any
	// registered message handling functions. the unmarshaler should be a
	// function that returns a fresh object of type proto.TaggedUnmarshaler,
	// ready to read in the bytes for an object marked as tpe.
	//
	// the string type associated with unmarshaler is the result of calling
	// Type() on a raw unmarshaler
	RegisterUnmashaler(unmarshaler func() TaggedMarshaler) error

	// SetFilter registers a broadcast channel filter which will be used
	// to determine if given broadcast channel message should be processed
	// by the receivers
	SetFilter(filter BroadcastChannelFilter) error
}

// BroadcastChannelFilter represents a filter which determine if the incoming
// message should be processed by the receivers. it takes the message author's
// public key as its argument and returns true if the message should be
// processed of false otherwise
type BroadcastChannelFilter func(*ecdsa.PublicKey) bool

// Firewall represents a set of rules that remote peer has to conform so that
// a connect with that peer can be approved
type Firewall interface {

	// Validate takes the remote public key and executes all the checks
	// needed to decide whether the connection with the peer can be approved.
	// If expectations are not met, this function should return an error
	// describe what is wrong
	Validate(remotePublicKey *ecdsa.PublicKey) error
}
