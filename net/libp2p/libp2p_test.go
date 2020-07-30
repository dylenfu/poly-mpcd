package libp2p

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/polynetwork/mpcd/net"
	"github.com/polynetwork/mpcd/net/key"
	"github.com/polynetwork/mpcd/net/retransmission"
)

func TestProviderReturnsType(t *testing.T) {
	ctx, cancel := newTestContext()
	defer cancel()

	privKey, _, err := key.GenerateStaticNetworkKey()
	if err != nil {
		t.Fatal(err)
	}

	expectedType := "libp2p"
	provider, err := Connect(
		ctx,
		generateDeterministicNetworkConfig(),
		privKey,
		ProtocolBeacon,
		FirewallDisabled,
		idleTicker(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if provider.Type() != expectedType {
		t.Fatalf("expected: provider type [%s]\nactual:   provider type [%s]",
			provider.Type(),
			expectedType,
		)
	}
}

func TestProviderReturnsChannel(t *testing.T) {
	ctx, cancel := newTestContext()
	defer cancel()

	testName := "testname"

	privKey, _, err := key.GenerateStaticNetworkKey()
	if err != nil {
		t.Fatal(err)
	}

	provider, err := Connect(
		ctx,
		generateDeterministicNetworkConfig(),
		privKey,
		ProtocolBeacon,
		FirewallDisabled,
		idleTicker(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = provider.BroadcastChannelFor(testName); err != nil {
		t.Fatalf("expected: test to fail with [%v]\nactual:   failed with [%v]",
			nil,
			err,
		)
	}
}

func TestSendReceive(t *testing.T) {
	ctx, cancel := newTestContext()
	defer cancel()

	var (
		config          = generateDeterministicNetworkConfig()
		name            = "testchannel"
		expectedPayload = "some text"
	)

	privKey, _, err := key.GenerateStaticNetworkKey()
	if err != nil {
		t.Fatal(err)
	}

	identity, err := createIdentity(privKey)
	if err != nil {
		t.Fatal(err)
	}

	provider, err := Connect(
		ctx,
		config,
		privKey,
		ProtocolBeacon,
		FirewallDisabled,
		idleTicker(),
	)
	if err != nil {
		t.Fatal(err)
	}
	broadcastChannel, err := provider.BroadcastChannelFor(name)
	if err != nil {
		t.Fatal(err)
	}

	if err := broadcastChannel.RegisterUnmarshaler(
		func() net.TaggedUnmarshaler { return &testMessage{} },
	); err != nil {
		t.Fatal(err)
	}

	if err := broadcastChannel.Send(
		ctx,
		&testMessage{Sender: identity, Payload: expectedPayload},
	); err != nil {
		t.Fatal(err)
	}

	recvChan := make(chan net.Message)
	broadcastChannel.Recv(ctx, func(msg net.Message) {
		recvChan <- msg
	})

	for {
		select {
		case msg := <-recvChan:
			testPayload, ok := msg.Payload().(*testMessage)
			if !ok {
				t.Fatalf(
					"expected: payload type string\nactual:   payload type [%v]",
					testPayload,
				)
			}

			if expectedPayload != testPayload.Payload {
				t.Fatalf(
					"expected: message payload [%s]\ngot:   payload [%s]",
					expectedPayload,
					testPayload.Payload,
				)
			}
			return
		case <-ctx.Done():
			t.Fatal(err)
		}
	}
}

func TestProviderSetAnnouncedAddresses(t *testing.T) {
	ctx, cancel := newTestContext()
	defer cancel()

	privateKey, _, err := key.GenerateStaticNetworkKey()
	if err != nil {
		t.Fatal(err)
	}

	config := generateDeterministicNetworkConfig()
	config.AnnouncedAddresses = []string{
		"/bad/address",
		"/dns4/address.com/tcp/3919",
		"totallyBadAddress",
		"/ip4/100.20.50.30/tcp/3919",
	}

	provider, err := Connect(
		ctx,
		config,
		privateKey,
		ProtocolBeacon,
		FirewallDisabled,
		idleTicker(),
	)
	if err != nil {
		t.Fatal(err)
	}

	expectedAddresses := []string{
		fmt.Sprintf("/dns4/address.com/tcp/3919/ipfs/%v", provider.ID()),
		fmt.Sprintf("/ip4/100.20.50.30/tcp/3919/ipfs/%v", provider.ID()),
	}
	providerAddresses := provider.ConnectionManager().AddrStrings()
	if strings.Join(expectedAddresses, " ") != strings.Join(providerAddresses, " ") {
		t.Fatalf(
			"expected: provider addresses [%v]\nactual: provider addresses [%v]",
			expectedAddresses,
			providerAddresses,
		)
	}
}

type testMessage struct {
	Sender    *identity
	Recipient *identity
	Payload   string
}

func (m *testMessage) Type() string {
	return "test/unmarshaler"
}

func (m *testMessage) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

func (m *testMessage) Unmarshal(bytes []byte) error {
	var message testMessage
	if err := json.Unmarshal(bytes, &message); err != nil {
		return err
	}
	m.Sender = message.Sender
	m.Recipient = message.Recipient
	m.Payload = message.Payload

	return nil
}

func newTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func idleTicker() *retransmission.Ticker {
	ticks := make(chan uint64)
	close(ticks)
	return retransmission.NewTicker(ticks)
}

func generateDeterministicNetworkConfig() Config {
	return Config{Port: 8080}
}

// FirewallDisabled is an empty Firewall implementation enforcing no rules
// on the connection.
var FirewallDisabled = &noFirewall{}

type noFirewall struct{}

func (nf *noFirewall) Validate(remotePeerPublicKey *ecdsa.PublicKey) error {
	return nil
}
