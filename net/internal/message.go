package internal

import (
	"github.com/polynetwork/mpcd/net"
)

// BaseMessage instance an basic message
func BaseMessage(
	transportSenderID net.TransportIdentifier,
	senderPublicKey []byte,
	payload interface{},
	messageType string,
	seqno uint64,
) net.Message {
	return &basicMessage{
		transportSenderID,
		senderPublicKey,
		payload,
		messageType,
		seqno,
	}
}

// baseMessage is a struct-based trival implementation for net.Message,
// interface for use by packages that don't need any frills
type basicMessage struct {
	transportSenderID net.TransportIdentifier
	senderPublicKey   []byte
	payload           interface{}
	messageType       string
	seqno             uint64
}

func (m *basicMessage) TransportSenderID() net.TransportIdentifier {
	return m.transportSenderID
}

func (m *basicMessage) SenderPublicKey() []byte {
	return m.senderPublicKey
}

func (m *basicMessage) Payload() interface{} {
	return m.payload
}

func (m *basicMessage) Type() string {
	return m.messageType
}

func (m *basicMessage) Seqno() uint64 {
	return m.seqno
}
