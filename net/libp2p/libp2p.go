package libp2p

import "github.com/ipfs/go-log"

var logger = log.Logger("mpcd-net-libp2p")

// Config defines the configuration for the libp2p network provider.
type Config struct {
	Peers              []string
	Port               int
	AnnouncedAddresses []string
	DisseminationTime  int
}

// Keep Network protocol identifiers
const (
	ProtocolBeacon = "mpcd-beacon"
	ProtocolECDSA  = "mpcd-ecdsa"
)
