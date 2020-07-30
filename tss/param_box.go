package tss

import (
	"fmt"

	"github.com/binance-chain/tss-lib/ecdsa/keygen"
)

// Box is a container for tss key generation parameters. box lets to
// get its connect as well as to destroy it.
//
// This type is useful for passing pre-parameters around for retired
// key generation attempts. generating pre-params is very expensive
// and we don't want to re-generate them for every key generation retry
// attempt. on the other hand, pre-parameters can't be reused once they were
// used for communication with other clients.
//
// For this reason, instead of passing raw pre-parameters to key generation,
// we can pass a box. when the node shares its pre parameters with other nodes,
// box content should be destroyed. until then, it's fine to pass the box
// around and consume its content for any calculations needed between retried
// key-generation attempts.
type Box struct {
	params *keygen.LocalPreParams
}

// NewBox creates a new PreParamsBox with the provided key generation pre-params
func NewBox(params *keygen.LocalPreParams) *Box {
	return &Box{params}
}

// Content gets the box content or error if the content has been destroyed
func (b *Box) Content() (*keygen.LocalPreParams, error) {
	if b.IsEmpty() {
		return nil, fmt.Errorf("box is empty")
	}
	return b.params, nil
}

// IsEmpty returns true if tht box content has been destroyed.
// Otherwise, returns false.
func (b *Box) IsEmpty() bool {
	return b.params == nil
}

// DestroyContent destroys the box content so that all further calls to
// Content() function will fail
func (b *Box) DestroyContent() {
	b.params = nil
}
