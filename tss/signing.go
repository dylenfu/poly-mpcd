package tss

import (
	"context"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/tss"
)

// initializeSigning initializes a member to run a threshold multi-party signature
// calculation protocol. signature will be calculated for provided digest.
func (s *ThresholdSigner) initializeSigning(
	ctx context.Context,
	digest []byte,
	netBridge *networkBridge,
) (*signingSigner, error) {

	digestInt := new(big.Int).SetBytes(digest)

	party, endChan, err := s.initializeSigningParty(
		ctx,
		digestInt,
		netBridge,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signing party: [%v]", err)
	}

	return &signingSigner{
		groupInfo:      s.groupInfo,
		networkBridge:  netBridge,
		signingParty:   party,
		signingEndChan: endChan,
	}, nil
}

// signingSigner represents signer who initialized signing stage and is ready to
// start signature calculation.
type signingSigner struct {
	*groupInfo

	// network bridge used for message transport.
	networkBridge *networkBridge
	// party for tss protocol execution.
	signingParty tss.Party
	// channel where a result of the signing protocol execution will be written to.
	signingEndChan <-chan common.SignatureData
}

// sign executes the protocol to calculate a signature. this function needs to be
// executed only after all members finished the initialization stage. as a result
// the calculate ECDSA signature will be returned or an error, if the signature
// generation failed
func (s *signingSigner) sign(ctx context.Context) (*Signature, error) {
	if s.signingParty == nil {
		return nil, fmt.Errorf("failed to get initialized signing party")
	}

	if err := s.signingParty.Start(); err != nil {
		return nil, fmt.Errorf("failed to start signing: [%v]", s.signingParty.WrapError(err))
	}

	// todo(fuk): support concurrent sign in single goroutine
	for {
		select {
		case signature := <-s.signingEndChan:
			ecdsaSignature := convertSignatureTSSToECDSA(signature)
			return &ecdsaSignature, nil

		case <-ctx.Done():
			memberIDs := []MemberID{}

			if s.signingParty.WaitingFor() != nil {
				for _, partyID := range s.signingParty.WaitingFor() {
					memberID, err := MemberIDFromString(partyID.GetId())
					if err != nil {
						logger.Errorf("cannot get member id from string [%v]: [%v]",
							partyID.GetId(), err)
						continue
					}
					memberIDs = append(memberIDs, memberID)
				}
			}

			return nil, timeoutError{
				timeout:   SigningProtocolTimeout,
				stage:     "signing",
				memberIDs: memberIDs,
			}
		}
	}
}

func (s *ThresholdSigner) initializeSigningParty(
	ctx context.Context,
	digest *big.Int,
	netBridge *networkBridge,
) (
	tss.Party,
	<-chan common.SignatureData,
	error) {

	tssMessageChan := make(chan tss.Message, len(s.groupMemberIDs))
	endChan := make(chan common.SignatureData)

	currentPartyID, groupPartiesIDs, err := generatePartiesIDs(
		s.memberID,
		s.groupMemberIDs,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate parties IDs: [%v]", err)
	}

	params := tss.NewParameters(
		tss.NewPeerContext(tss.SortPartyIDs(groupPartiesIDs)),
		currentPartyID,
		len(groupPartiesIDs),
		s.dishonestThreshold,
	)

	party := signing.NewLocalParty(
		digest,
		params,
		keygen.LocalPartySaveData(s.thresholdKey),
		tssMessageChan,
		endChan,
	)

	if err := netBridge.connect(
		ctx,
		tssMessageChan,
		party,
		params.Parties().IDs(),
	); err != nil {
		return nil, nil, fmt.Errorf("failed to connect bridge network: [%v]", err)
	}

	return party, endChan, nil
}

func convertSignatureTSSToECDSA(tssSignature common.SignatureData) Signature {
	// `SignatureData` contains recovery ID as a byte slice. only the first
	// byte is relevant and is converted to `int`
	recoverBytes := tssSignature.GetSignatureRecovery()
	recoverInt := int(0)
	recoverInt = (recoverInt << 8) | int(recoverBytes[0])

	return Signature{
		R:          new(big.Int).SetBytes(tssSignature.GetR()),
		S:          new(big.Int).SetBytes(tssSignature.GetS()),
		RecoveryID: recoverInt,
	}
}
