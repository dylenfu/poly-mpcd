package tss

import (
	"github.com/ipfs/go-log"
	"time"
)

var logger = log.Logger("mpcd-tss")

const (
	KeyGenerationProtocolTimeout = 8 * time.Minute
	SigningProtocolTimeout       = 10 * time.Minute
)
