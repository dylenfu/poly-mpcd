package watchowner

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"sync"
	"time"

	"github.com/ipfs/go-log"
	"github.com/polynetwork/mpcd/net"
	"github.com/polynetwork/mpcd/net/key"
)

var logger = log.Logger("mpcd-watch-owner")

// Guard contains the state nessary to make connection puring decisions.
type Guard struct {
	duration time.Duration

	firewall net.Firewall

	connectionManager net.ConnectionManager

	peerCrossList     map[string]bool
	peerCrossListLock sync.Mutex
}

// NewGuard returns a new instance of Guard. should only be called once per provider.
// instantiating a new instance of Guard automatically runs it in the backgroud
// for the lifetime of the client.
func NewGuard(
	ctx context.Context,
	duration time.Duration,
	firewall net.Firewall,
	connectionManager net.ConnectionManager) *Guard {

	guard := &Guard{
		duration:          duration,
		firewall:          firewall,
		connectionManager: connectionManager,
		peerCrossList:     make(map[string]bool),
	}

	go guard.start(ctx)
	return guard
}

func (g *Guard) currentlyChecking(peer string) bool {
	g.peerCrossListLock.Lock()
	checking, _ := g.peerCrossList[peer]
	g.peerCrossListLock.Unlock()
	return checking
}

func (g *Guard) markAsChecking(peer string) {
	g.peerCrossListLock.Lock()
	g.peerCrossList[peer] = true
	g.peerCrossListLock.Unlock()
}

func (g *Guard) completeCheck(peer string) {
	g.peerCrossListLock.Lock()
	g.peerCrossList[peer] = false
	g.peerCrossListLock.Unlock()
}

// start execute the connection management backgroud worker.
// if it receives a signal to stop the execution of the client,
// it kills this task.
func (g *Guard) start(ctx context.Context) {
	ticker := time.NewTicker(g.duration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			logger.Debug("start firewall guard round")

			connectedPeers := g.connectionManager.ConnectedPeers()

			for _, connectedPeer := range connectedPeers {
				if g.currentlyChecking(connectedPeer) {
					continue
				}

				g.markAsChecking(connectedPeer)
				go g.checkFirewallRules(connectedPeer)
			}
		}
	}
}

func (g *Guard) checkFirewallRules(peer string) {
	defer g.completeCheck(peer)

	peerPublicKey, err := g.getPeerPublicKey(peer)
	if err != nil {
		logger.Errorf("dropping the connection; could not get the public key for peer [%s]: [%v]", peer, err)
		g.connectionManager.DisconnectPeer(peer)
		return
	}

	if err := g.firewall.Validate(peerPublicKey); err != nil {
		logger.Errorf("dropping the connection; firewall rules not satisfied for peer [%s]: [%v]", peer, err)
		g.connectionManager.DisconnectPeer(peer)
	}
}

func (g *Guard) getPeerPublicKey(peer string) (*ecdsa.PublicKey, error) {
	peerPublicKey, err := g.connectionManager.GetPeerPublicKey(peer)
	if err != nil {
		return nil, err
	}

	if peerPublicKey == nil {
		return nil, fmt.Errorf("failed to resolved public key for peer [%s]", peer)
	}

	return key.NetworkKeyToECDSAKey(peerPublicKey), nil
}
