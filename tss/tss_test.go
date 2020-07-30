package tss

import (
	"fmt"

	"github.com/polynetwork/mpcd/net"
	"github.com/polynetwork/mpcd/net/key"
	"github.com/polynetwork/mpcd/net/local"
	"github.com/polynetwork/mpcd/operator"
)

func generateMemberKeys(groupSize int) ([]MemberID, error) {
	memberIDs := []MemberID{}

	for i := 0; i < groupSize; i++ {
		_, publicKey, err := operator.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate operator key: [%v]", err)
		}

		memberIDs = append(memberIDs, MemberIDFromPublicKey(publicKey))
	}

	return memberIDs, nil
}

func newTestNetProvider(memberNetworkKey *key.NetworkPublic) net.Provider {
	return local.ConnectWithKey(memberNetworkKey)
}
