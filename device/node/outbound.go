package node

import (
	"sync"
	"time"

	"github.com/kabili207/lxmf-go/core"
)

const (
	maxDeliveryAttempts = 5
	processingInterval  = 4 * time.Second
	deliveryRetryWait   = 10 * time.Second
	pathRequestWait     = 7 * time.Second
)

// outboundEntry tracks an outbound message queued for delivery with retry.
type outboundEntry struct {
	DestHash []byte
	Message  *core.LXMessage
	Packed   []byte
	Method   DeliveryMethod

	Attempts         int
	NextAttempt      time.Time
	State            core.State
}

// outboundQueue manages pending outbound LXMF messages with retry logic.
type outboundQueue struct {
	mu      sync.Mutex
	entries []*outboundEntry
}

func (q *outboundQueue) add(e *outboundEntry) {
	q.mu.Lock()
	q.entries = append(q.entries, e)
	q.mu.Unlock()
}

// ready returns entries that are due for a delivery attempt and haven't
// exceeded the max attempts or been completed/failed.
func (q *outboundQueue) ready() []*outboundEntry {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	var result []*outboundEntry
	for _, e := range q.entries {
		if e.State == core.StateSent || e.State == core.StateDelivered ||
			e.State == core.StateFailed || e.State == core.StateCancelled {
			continue
		}
		if now.Before(e.NextAttempt) {
			continue
		}
		result = append(result, e)
	}
	return result
}

// remove removes completed or failed entries and returns them.
func (q *outboundQueue) removeFinished() []*outboundEntry {
	q.mu.Lock()
	defer q.mu.Unlock()

	var kept []*outboundEntry
	var removed []*outboundEntry
	for _, e := range q.entries {
		switch e.State {
		case core.StateDelivered, core.StateFailed, core.StateCancelled:
			removed = append(removed, e)
		case core.StateSent:
			// For opportunistic delivery, SENT is terminal (no confirmation).
			if e.Method == DeliveryOpportunistic {
				removed = append(removed, e)
			} else {
				kept = append(kept, e)
			}
		default:
			kept = append(kept, e)
		}
	}
	q.entries = kept
	return removed
}

// markState updates the state of the entry matching the given message hash.
func (q *outboundQueue) markState(msgHash []byte, state core.State) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, e := range q.entries {
		if len(e.Message.Hash) > 0 && bytesEqual(e.Message.Hash, msgHash) {
			e.State = state
			return
		}
	}
}

// pending returns the number of entries that haven't reached a terminal state.
func (q *outboundQueue) pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	count := 0
	for _, e := range q.entries {
		switch e.State {
		case core.StateDelivered, core.StateFailed, core.StateCancelled:
			continue
		case core.StateSent:
			if e.Method == DeliveryOpportunistic {
				continue
			}
		}
		count++
	}
	return count
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
