package tss

import (
	"context"
	"fmt"
	"time"

	"github.com/ipfs/go-log"
	"github.com/polynetwork/mpcd/net"
)

var logger = log.Logger("mpcd-tss")

const (
	KeyGenerationProtocolTimeout = 8 * time.Minute
	SigningProtocolTimeout       = 10 * time.Minute
)

// GenerateThresholdSigner executes a threshold multi-party key generation protocol.
//
// it expects unique identifiers of the current member as well as identifiers of
// all members of the signing group. group id should be unique for each concurrent
// execution.
//
// dishonest threshold `t` defines a maximum number of signers controlled by the
// adversary such tha the adversary still cannot produce a signature. any subnet
// of `t + 1` players can jointly sign, but any smaller subset cannot.
//
// tss protocol requires pre-parameters such as safe primes to be generated for
// execution. the parameters should be generated prior to running this function.
// if not provided they will be generated.
//
// as a result a signer will be returned or an error, if key generation failed.
func GenerateThresholdSigner(
	parentCtx context.Context,
	groupID string,
	memberID MemberID,
	groupMemberIDs []MemberID,
	dishonestThreshold int,
	networkProvider net.Provider,
	paramsBox *ParamBox,
) (*ThresholdSigner, error) {

	if len(groupMemberIDs) < 2 {
		return nil, fmt.Errorf("group should have at least 2 members but got: [%d]", len(groupMemberIDs))
	}

	if len(groupMemberIDs) < int(dishonestThreshold) {
		return nil, fmt.Errorf("group size [%d], should be greater than dishonest threshold [%d]",
			len(groupMemberIDs), dishonestThreshold)
	}

	group := &groupInfo{
		groupID:            groupID,
		memberID:           memberID,
		groupMemberIDs:     groupMemberIDs,
		dishonestThreshold: dishonestThreshold,
	}

	networkBridge, err := newNetworkBridge(group, networkProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to initilize network bridge: [%v]", err)
	}

	ctx, cancel := context.WithTimeout(parentCtx, KeyGenerationProtocolTimeout)
	defer cancel()

	preParams, err := paramsBox.Content()
	if err != nil {
		return nil, fmt.Errorf("failed to get pre-parameters: [%v]", err)
	}

	keygenSigner, err := initializeKeyGeneration(
		ctx,
		group,
		preParams,
		networkBridge,
	)
	if err != nil {
		return nil, err
	}

	logger.Infof("[party:%v]: initialized key generation", keygenSigner.keygenParty.PartyID())

	broadcastChannel, err := networkBridge.getBroadcastChannel()
	if err != nil {
		return nil, err
	}

	if err := readyProtocol(ctx, group, broadcastChannel); err != nil {
		return nil, fmt.Errorf("readiness signaling protocol failed: [%v]", err)
	}

	// We are beginning the communication with other members using pre-parameters
	// provided inside of this box. it's time to destroy box content so that the
	// pre-parameters cannot be later reused.
	paramsBox.DestroyContent()

	logger.Infof("[party:%v]: starting key generation", keygenSigner.keygenParty.PartyID())

	signer, err := keygenSigner.generateKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: [%v]", err)
	}

	logger.Infof("[party:%v]: completed key generation", keygenSigner.keygenParty.PartyID())

	return signer, nil
}

// CalculateSignature executes a threshold multi-party signature calculation
// protocol for the given digest. as a result the calculated ECDSA signature will
// be returned or an error, if the signature generation failed.
func (s *ThresholdSigner) CalculateSignature(
	parentCtx context.Context,
	digest []byte,
	networkProvider net.Provider,
) (*Signature, error) {

	networkBridge, err := newNetworkBridge(s.groupInfo, networkProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize network bridge: [%v]", err)
	}

	ctx, cancel := context.WithTimeout(parentCtx, SigningProtocolTimeout)
	defer cancel()

	signingSigner, err := s.initializeSigning(ctx, digest[:], networkBridge)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signing: [%v]", err)
	}

	broadcastChannel, err := networkBridge.getBroadcastChannel()
	if err != nil {
		return nil, err
	}

	if err := readyProtocol(ctx, s.groupInfo, broadcastChannel); err != nil {
		return nil, fmt.Errorf("readiness signaling protocol failed: [%v]", err)
	}

	signature, err := signingSigner.sign(ctx)
	if err != nil {
		return nil, fmt.Errorf("faild to sign: [%v]", err)
	}

	return signature, nil
}
