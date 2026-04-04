package core

import (
	"crypto/rand"
	"sync"
	"time"
)

const (
	// TicketLength is the size of a ticket in bytes (truncated hash).
	TicketLength = TruncatedHashSize // 16 bytes

	// TicketExpiry is how long a generated inbound ticket remains valid.
	TicketExpiry = 21 * 24 * time.Hour

	// TicketGrace is the grace period after expiry before an inbound ticket
	// is removed from storage.
	TicketGrace = 5 * 24 * time.Hour

	// TicketRenew is the remaining validity threshold below which a new
	// ticket is generated instead of reusing an existing one.
	TicketRenew = 14 * 24 * time.Hour

	// TicketInterval is the minimum time between ticket deliveries to the
	// same destination.
	TicketInterval = 24 * time.Hour
)

// inboundTicket is a ticket we generated and sent to a peer so they can skip
// PoW on their next message to us.
type inboundTicket struct {
	Ticket  []byte
	Expires time.Time
}

// outboundTicket is a ticket a peer sent us so we can skip PoW when sending
// to them.
type outboundTicket struct {
	Ticket  []byte
	Expires time.Time
}

// TicketStore manages PoW bypass tickets for the LXMF router. It tracks
// tickets we've generated for peers (inbound) and tickets peers have given
// us (outbound).
type TicketStore struct {
	mu sync.Mutex

	// inbound tickets: keyed by hex destination hash, each destination can
	// have multiple active tickets.
	inbound map[string][]inboundTicket

	// outbound tickets: keyed by hex destination hash.
	outbound map[string]outboundTicket

	// lastDeliveries tracks when we last delivered a ticket to each
	// destination, to enforce TicketInterval spacing.
	lastDeliveries map[string]time.Time
}

// NewTicketStore creates an empty ticket store.
func NewTicketStore() *TicketStore {
	return &TicketStore{
		inbound:        make(map[string][]inboundTicket),
		outbound:       make(map[string]outboundTicket),
		lastDeliveries: make(map[string]time.Time),
	}
}

// GenerateTicket creates a ticket for the given destination hash (hex-encoded)
// that we can include in an outbound message so the recipient can bypass PoW
// on their reply.
//
// Returns [expires, ticketBytes] or nil if a ticket was already delivered
// recently or an existing ticket still has enough validity.
func (ts *TicketStore) GenerateTicket(destHex string) (expires time.Time, ticket []byte, ok bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()

	// Check delivery interval.
	if last, found := ts.lastDeliveries[destHex]; found {
		if now.Sub(last) < TicketInterval {
			return time.Time{}, nil, false
		}
	}

	// Reuse an existing ticket if it has enough validity left.
	if tickets, found := ts.inbound[destHex]; found {
		for _, t := range tickets {
			if t.Expires.Sub(now) > TicketRenew {
				return t.Expires, t.Ticket, true
			}
		}
	}

	// Generate a new ticket.
	ticket = make([]byte, TicketLength)
	if _, err := rand.Read(ticket); err != nil {
		return time.Time{}, nil, false
	}

	expires = now.Add(TicketExpiry)
	ts.inbound[destHex] = append(ts.inbound[destHex], inboundTicket{
		Ticket:  ticket,
		Expires: expires,
	})

	return expires, ticket, true
}

// RecordTicketDelivery marks that a ticket was delivered to the given
// destination, updating the last delivery timestamp.
func (ts *TicketStore) RecordTicketDelivery(destHex string) {
	ts.mu.Lock()
	ts.lastDeliveries[destHex] = time.Now()
	ts.mu.Unlock()
}

// RememberTicket stores a ticket received from a peer so we can use it to
// bypass PoW when sending to them.
func (ts *TicketStore) RememberTicket(sourceHex string, expires time.Time, ticket []byte) {
	if expires.Before(time.Now()) {
		return
	}
	ts.mu.Lock()
	ts.outbound[sourceHex] = outboundTicket{
		Ticket:  ticket,
		Expires: expires,
	}
	ts.mu.Unlock()
}

// GetOutboundTicket returns a valid outbound ticket for the destination, or
// nil if none is available.
func (ts *TicketStore) GetOutboundTicket(destHex string) []byte {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry, found := ts.outbound[destHex]
	if !found || entry.Expires.Before(time.Now()) {
		return nil
	}
	return entry.Ticket
}

// GetInboundTickets returns all valid inbound tickets for the given source
// destination hash. These are tickets we generated and sent to that peer.
// Returns nil if none are available.
func (ts *TicketStore) GetInboundTickets(sourceHex string) [][]byte {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	entries, found := ts.inbound[sourceHex]
	if !found {
		return nil
	}

	var tickets [][]byte
	for _, t := range entries {
		if now.Before(t.Expires) {
			tickets = append(tickets, t.Ticket)
		}
	}
	if len(tickets) == 0 {
		return nil
	}
	return tickets
}

// Clean removes expired tickets and stale delivery records.
func (ts *TicketStore) Clean() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()

	// Clean outbound.
	for k, entry := range ts.outbound {
		if entry.Expires.Before(now) {
			delete(ts.outbound, k)
		}
	}

	// Clean inbound (with grace period).
	for k, entries := range ts.inbound {
		var valid []inboundTicket
		for _, t := range entries {
			if now.Before(t.Expires.Add(TicketGrace)) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(ts.inbound, k)
		} else {
			ts.inbound[k] = valid
		}
	}
}
