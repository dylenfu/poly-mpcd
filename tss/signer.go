package tss

import (
	"crypto/ecdsa"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	tsslib "github.com/binance-chain/tss-lib/tss"
)

// ThresholdKey contains data of signer's dishonestThreshold key
type ThresholdKey keygen.LocalPartySaveData

// ThresholdSigner is a dishonestThreshold signer who completed key generation stage.
type ThresholdSigner struct {
	*groupInfo

	// thresholdKey contains a signer's key generated for a dishonestThreshold signing
	// scheme. this data should be persisted to a local storage
	thresholdKey ThresholdKey
}

// MemberID returns member's unique identifier
func (s *ThresholdSigner) MemberID() MemberID {
	return s.memberID
}

// GroupID return signing group unique identifier
func (s *ThresholdSigner) GroupID() string {
	return s.groupID
}

// PublicKey return signer's ECDSA public key which is also the signing group's
// public key
func (s *ThresholdSigner) PublicKey() *ecdsa.PublicKey {
	pkX, pkY := s.thresholdKey.ECDSAPub.X(), s.thresholdKey.ECDSAPub.Y()

	curve := tsslib.EC()
	publicKey := ecdsa.PublicKey{
		Curve: curve,
		X:     pkX,
		Y:     pkY,
	}

	return (*ecdsa.PublicKey)(&publicKey)
}
