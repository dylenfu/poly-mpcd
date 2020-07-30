package tss

import (
	"bytes"
	"encoding/hex"
	"math/big"

	"github.com/polynetwork/mpcd/operator"
)

// MemberID is an unique identifier of a member across the network.
type MemberID []byte

// MemberIDFromPublicKey create a MemberID from a public key
func MemberIDFromPublicKey(publicKey *operator.PublicKey) MemberID {
	return operator.Marshal(publicKey)
}

// PublicKey returns the MemberID as a public key
func (id MemberID) PublicKey() (*operator.PublicKey, error) {
	return operator.Unmarshal(id)
}

// MemberIDFromString create a MemberID from a hex string
func MemberIDFromString(str string) (MemberID, error) {
	return hex.DecodeString(str)
}

// String converts MemberID to string
func (id MemberID) String() string {
	return hex.EncodeToString(id)
}

// bigInt convert MemberID to big.Int
func (id MemberID) bigInt() *big.Int {
	return new(big.Int).SetBytes(id)
}

// Equal checks if member IDs are equal
func (id MemberID) Equal(memberID MemberID) bool {
	return bytes.Equal(id, memberID)
}

// groupInfo holds information about the group selected for protocol execution.
type groupInfo struct {
	groupID        string // globally unique group identifier
	memberID       MemberID
	groupMemberIDs []MemberID

	// Dishonest threshold `t` defines a maximum number of signers controlled by the
	// adversary such that the adversary still cannot produce a signature. Any subset
	// of `t + 1` players can jointly sign, but any smaller subset cannot.
	//
	// it denote as `threshold` in bianance-chain/tss-lib
	dishonestThreshold int
}
