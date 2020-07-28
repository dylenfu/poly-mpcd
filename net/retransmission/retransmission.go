// Package retransmission implements a simple retransmission mechanism
// for network message based on their sequnce number. retransmitting message
// several times for the lifetime of the given phase helps to imporve message
// delivery rate for senders and receivers who are not perfectly synced on time.
package retransmission

import (
	"context"
	"fmt"
	"sync"

	"github.com/ipfs/go-log"
	"github.com/polynetwork/mpcd/net"
)

var logger = log.Logger("mpcd-net-retransmisssion")

// ScheduleRetransmissions takes the provided message and retransmit it
// for every new tick received from the provided ticker for the entire lifetime
// of the context calling the provided retransmit function. the retransmit function
// has to guarantee that every call from this function sends a message with the same
// sequence number.
func ScheduleRetransmissions(
	ctx context.Context,
	ticker *Ticker,
	retransmit func() error,
) {
	go func() {
		ticker.onTick(ctx, func() {
			go func() {
				if err := retransmit(); err != nil {
					logger.Errorf("could not retransmit message, err %v", err)
				}
			}()
		})
	}()
}

// WithRetransmissionSupport takes standard network message handler and
// enhance it with functionally allowing to handle retransmission.
// the returned handler filters out retransmissions and calls the delegate
// handler only if the received message is not a retrnasmission or if it is
// a retransmission but it has not been seen by the original handler yet.
// the returned handler is thread-safe.
//
// the retransmission is identified by sender transport ID and message sequence
// number. two messages with the same sender ID and sequnce number are considered
// the same. handlers cann't be reused between channels if sequnce number of message
// is local for channel.
func WithRetransmissionSupport(delegate func(m net.Message)) func(m net.Message) {
	mutex := &sync.Mutex{}
	cache := make(map[string]bool)

	return func(message net.Message) {
		messageID := fmt.Sprintf(
			"%v-%v",
			message.TransportSenderID().String(),
			message.Seqno(),
		)

		mutex.Lock()
		_, seen := cache[messageID]
		if !seen {
			cache[messageID] = true
		}
		mutex.Unlock()

		if !seen {
			delegate(message)
		}
	}
}
