package libp2p

import "github.com/ipfs/go-log"

var logger = log.Logger("mpcd-net-libp2p")

// Keep Network protocol identifiers
const (
	ProtocolBeacon = "mpcd-beacon"
	ProtocolECDSA  = "mpcd-ecdsa"
)
