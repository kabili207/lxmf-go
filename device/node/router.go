// Package node provides the LXMRouter, the primary entrypoint for sending
// and receiving LXMF messages over a Reticulum network.
package node

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/kabili207/lxmf-go/core"
	"github.com/kabili207/lxmf-go/device/event"
	rns "github.com/svanichkin/go-reticulum/rns"
)

const (
	// deliveryAspectName is the full destination name used for computing
	// backchannel link keys from a remote identity.
	deliveryAspectName = core.AppName + "." + core.DeliveryAspect

	// resourceTimeout is the timeout in seconds for resource transfers.
	resourceTimeout = 300.0
)

// DeliveryMethod controls how outbound messages are sent.
type DeliveryMethod int

const (
	// DeliveryOpportunistic sends a single packet with no link establishment
	// and no delivery confirmation. Best-effort.
	DeliveryOpportunistic DeliveryMethod = iota

	// DeliveryDirect establishes an RNS link to the recipient before sending.
	// Provides delivery confirmation via link-level proof.
	DeliveryDirect
)

// RouterConfig holds configuration for an LXMRouter.
type RouterConfig struct {
	// Identity is the RNS identity for this LXMF node. If nil, a new ephemeral
	// identity is generated on startup.
	Identity *rns.Identity

	// DisplayName is included in announces so peers can show a human-readable
	// name. Defaults to "" (anonymous).
	DisplayName string

	// StampCost is the PoW cost we advertise. 0 means we do not require stamps.
	StampCost int

	// EnforceStamps controls whether inbound messages without valid stamps are
	// dropped. When false (default), stamps are validated and reported in the
	// event but all messages are accepted regardless.
	EnforceStamps bool

	// IncludeTickets controls whether outbound messages include a PoW bypass
	// ticket for the recipient so they can skip stamp generation on their
	// reply. Requires StampCost > 0 to be meaningful.
	IncludeTickets bool

	// Logger defaults to slog.Default() if nil.
	Logger *slog.Logger
}

// LXMRouter manages the LXMF delivery destination, handles inbound messages,
// and sends outbound messages to peers on a Reticulum network.
//
// Callers must call Start before sending or receiving messages.
type LXMRouter struct {
	cfg RouterConfig
	log *slog.Logger

	identity    *rns.Identity
	destination *rns.Destination // lxmf.delivery destination (IN/SINGLE)
	privKey     ed25519.PrivateKey

	mu       sync.RWMutex
	handlers []event.Handler

	tickets  *core.TicketStore
	outbound *outboundQueue
	stopCh   chan struct{}

	// deliveredMu protects deliveredIDs.
	deliveredMu  sync.Mutex
	deliveredIDs map[string]time.Time // hex(messageHash) → delivery time

	// stampCostsMu protects stampCosts.
	stampCostsMu sync.RWMutex
	stampCosts   map[string]stampCostEntry // hex(destHash) → cached stamp cost

	// linkMu protects the backchannel and direct link maps.
	linkMu           sync.Mutex
	backchannelLinks map[string]*rns.Link // hex(destHash) → inbound link (peer identified)
	directLinks      map[string]*rns.Link // hex(destHash) → outbound link we initiated
}

// stampCostEntry is a cached stamp cost learned from a peer announce.
type stampCostEntry struct {
	Cost    int
	Updated time.Time
}

const (
	stampCostExpiry = 45 * 24 * time.Hour

	// messageExpiry is how long message hashes are retained for dedup.
	// Python uses MESSAGE_EXPIRY*6 = 180 days.
	deliveredIDExpiry = 180 * 24 * time.Hour

	// cleanupInterval controls how often expired dedup entries are purged.
	cleanupInterval = 4 * time.Minute
)

// NewRouter creates a new LXMRouter. Call Start to begin processing.
func NewRouter(cfg RouterConfig) (*LXMRouter, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default().With("component", "lxmf")
	}

	return &LXMRouter{
		cfg:              cfg,
		log:              log,
		tickets:          core.NewTicketStore(),
		outbound:         &outboundQueue{},
		stopCh:           make(chan struct{}),
		deliveredIDs:     make(map[string]time.Time),
		stampCosts:       make(map[string]stampCostEntry),
		backchannelLinks: make(map[string]*rns.Link),
		directLinks:      make(map[string]*rns.Link),
	}, nil
}

// Start initializes the LXMF delivery destination and registers announce
// handlers. Reticulum must already be running (via rns.NewReticulum) before
// calling Start.
func (r *LXMRouter) Start() error {
	identity := r.cfg.Identity
	if identity == nil {
		var err error
		identity, err = rns.NewIdentity()
		if err != nil {
			return fmt.Errorf("create lxmf identity: %w", err)
		}
		r.log.Info("Generated new LXMF identity", "hash", identity.HexHash)
	}
	r.identity = identity

	// Extract Ed25519 private key from the RNS identity.
	// GetPrivateKey() returns [32-byte X25519 prv || 32-byte Ed25519 seed].
	privBytes := identity.GetPrivateKey()
	if len(privBytes) < 64 {
		return fmt.Errorf("identity private key too short: %d bytes", len(privBytes))
	}
	seed := privBytes[32:64]
	r.privKey = ed25519.NewKeyFromSeed(seed)

	// Create the lxmf.delivery destination.
	dest, err := rns.NewDestination(identity, rns.DestinationIN, rns.DestinationSINGLE, core.AppName, core.DeliveryAspect)
	if err != nil {
		return fmt.Errorf("create lxmf.delivery destination: %w", err)
	}
	r.destination = dest

	dest.SetPacketCallback(r.handlePacket)
	_ = dest.SetProofStrategy(rns.DestinationPROVE_ALL)

	// Set default app_data so that path responses (automatic announces triggered
	// by incoming path requests) include the correct display name and stamp cost.
	// Without this, path responses are sent with empty app_data.
	announceData, err := encodeAnnounceAppData(r.cfg.DisplayName, r.cfg.StampCost)
	if err == nil {
		dest.SetDefaultAppData(announceData)
	}

	// Accept incoming RNS links so peers using DIRECT delivery (e.g. MeshChat)
	// can establish a link and send LXMF messages over it.
	dest.AcceptsLinks(true)
	dest.SetLinkEstablishedCallback(r.handleLinkEstablished)

	// Register announce handler for peer discovery.
	rns.RegisterAnnounceHandler(&deliveryAnnounceHandler{router: r})

	r.log.Info("LXMF router started",
		"hash", fmt.Sprintf("%x", dest.Hash()),
		"name", r.cfg.DisplayName,
	)

	go r.processOutboundLoop()
	return nil
}

// Stop shuts down the background processing loop. The router should not be
// used after calling Stop.
func (r *LXMRouter) Stop() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
}

// Identity returns the RNS identity used by this router. Returns nil if the
// router has not been started. Callers can use this to create additional RNS
// destinations (e.g. nomadnetwork.node) that share the same identity.
func (r *LXMRouter) Identity() *rns.Identity {
	return r.identity
}

// DeliveryHash returns the 16-byte RNS truncated hash of this node's
// lxmf.delivery destination. This is the address peers use to send us messages.
func (r *LXMRouter) DeliveryHash() []byte {
	if r.destination == nil {
		return nil
	}
	return r.destination.Hash()
}

// Announce sends an lxmf.delivery announce to the network so peers can
// discover this node.
func (r *LXMRouter) Announce() error {
	if r.destination == nil {
		return fmt.Errorf("router not started")
	}
	appData, err := encodeAnnounceAppData(r.cfg.DisplayName, r.cfg.StampCost)
	if err != nil {
		return fmt.Errorf("encode announce app_data: %w", err)
	}
	r.destination.Announce(appData, false, nil, nil, true)
	r.log.Debug("Sent lxmf.delivery announce", "name", r.cfg.DisplayName)
	return nil
}

// Send queues an outbound LXMessage for delivery using the specified method.
// The message is signed, packed, and placed in the outbound queue. The
// background processing loop handles delivery attempts with retry.
//
// Send returns an error only if signing or packing fails. Delivery failures
// are reported asynchronously via DeliveryUpdate events.
func (r *LXMRouter) Send(destHash []byte, msg *core.LXMessage, method DeliveryMethod) error {
	if r.destination == nil {
		return fmt.Errorf("router not started")
	}

	msg.SourceHash = r.destination.Hash()
	msg.DestinationHash = destHash
	destHex := hex.EncodeToString(destHash)

	// Auto-configure stamp cost from cached peer announces if the caller
	// hasn't set one explicitly.
	if msg.StampCost == 0 {
		if cost := r.getStampCost(destHex); cost > 0 {
			msg.StampCost = cost
			r.log.Debug("Auto-configured stamp cost from announce",
				"to", fmt.Sprintf("%x", destHash[:8]),
				"cost", cost,
			)
		}
	}

	// If we have an outbound ticket from this peer, attach it so that Sign
	// can generate a cheap ticket-based stamp instead of mining PoW.
	if msg.StampCost > 0 {
		msg.OutboundTicket = r.tickets.GetOutboundTicket(destHex)
	}

	// Include a ticket for the recipient so they can skip PoW on their reply.
	if r.cfg.IncludeTickets && r.cfg.StampCost > 0 {
		if expires, ticket, ok := r.tickets.GenerateTicket(destHex); ok {
			msg.Fields[core.FieldTicket] = []any{
				float64(expires.Unix()),
				ticket,
			}
			r.tickets.RecordTicketDelivery(destHex)
		}
	}

	if err := msg.Sign(context.Background(), r.privKey); err != nil {
		return fmt.Errorf("sign message: %w", err)
	}

	packed, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("pack message: %w", err)
	}

	// Auto-escalate to DIRECT delivery if the packed message exceeds the
	// encrypted packet MDU.
	if method == DeliveryOpportunistic && len(packed)-core.DestHashSize > rns.PacketEncryptedMDU {
		r.log.Debug("Message too large for opportunistic delivery, escalating to direct",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"payload", len(packed)-core.DestHashSize,
			"encrypted_mdu", rns.PacketEncryptedMDU,
		)
		method = DeliveryDirect
	}

	// Pre-request a path for opportunistic delivery if we don't have one.
	nextAttempt := time.Now()
	if method == DeliveryOpportunistic && !rns.HasPath(destHash) {
		rns.RequestPath(destHash, nil)
		nextAttempt = time.Now().Add(pathRequestWait)
	}

	r.outbound.add(&outboundEntry{
		DestHash:    destHash,
		Message:     msg,
		Packed:      packed,
		Method:      method,
		State:       core.StateOutbound,
		NextAttempt: nextAttempt,
	})

	r.emit(&event.DeliveryUpdate{MessageHash: msg.Hash, State: core.StateOutbound})
	return nil
}

// processOutboundLoop runs in a background goroutine and periodically
// processes the outbound queue, retrying failed deliveries.
func (r *LXMRouter) processOutboundLoop() {
	ticker := time.NewTicker(processingInterval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(cleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-cleanupTicker.C:
			r.cleanDeliveredIDs()
			r.tickets.Clean()
			continue
		case <-ticker.C:
			r.processOutbound()
		}
	}
}

// processOutbound attempts delivery for all ready entries in the queue.
func (r *LXMRouter) processOutbound() {
	ready := r.outbound.ready()
	for _, e := range ready {
		if e.Attempts >= maxDeliveryAttempts {
			e.State = core.StateFailed
			r.log.Warn("Max delivery attempts reached",
				"to", fmt.Sprintf("%x", e.DestHash[:8]),
				"id", e.Message.ID(),
				"attempts", e.Attempts,
			)
			r.emit(&event.DeliveryUpdate{MessageHash: e.Message.Hash, State: core.StateFailed})
			continue
		}

		e.Attempts++
		e.State = core.StateSending

		switch e.Method {
		case DeliveryDirect:
			r.attemptDirect(e)
		default:
			r.attemptOpportunistic(e)
		}
	}

	// Clean up finished entries.
	r.outbound.removeFinished()
}

// attemptOpportunistic performs a single opportunistic delivery attempt.
func (r *LXMRouter) attemptOpportunistic(e *outboundEntry) {
	destHash := e.DestHash
	destKey := hex.EncodeToString(destHash)

	// Reuse an outbound link if available.
	if link := r.getActiveDirectLink(destKey); link != nil {
		r.sendOverLink(link, destHash, e.Packed, e.Message.Hash, e.Message.ID(), len(e.Message.Content))
		e.State = core.StateSent
		r.emit(&event.DeliveryUpdate{MessageHash: e.Message.Hash, State: core.StateSent})
		return
	}

	peerIdentity := rns.IdentityRecall(destHash)
	if peerIdentity == nil {
		r.log.Debug("Peer identity unknown, requesting path",
			"dest", fmt.Sprintf("%x", destHash[:8]),
			"attempt", e.Attempts,
		)
		rns.RequestPath(destHash, nil)
		e.NextAttempt = time.Now().Add(pathRequestWait)
		e.State = core.StateOutbound
		return
	}

	if !rns.HasPath(destHash) {
		r.log.Debug("No path yet, requesting",
			"dest", fmt.Sprintf("%x", destHash[:8]),
			"attempt", e.Attempts,
		)
		rns.RequestPath(destHash, nil)
		e.NextAttempt = time.Now().Add(pathRequestWait)
		e.State = core.StateOutbound
		return
	}

	outDest, err := rns.NewDestination(peerIdentity, rns.DestinationOUT, rns.DestinationSINGLE, core.AppName, core.DeliveryAspect)
	if err != nil {
		r.log.Warn("Failed to create outbound destination",
			"dest", fmt.Sprintf("%x", destHash[:8]),
			"error", err,
		)
		e.NextAttempt = time.Now().Add(deliveryRetryWait)
		e.State = core.StateOutbound
		return
	}

	payload := e.Packed[core.DestHashSize:]
	pkt := rns.NewPacket(outDest, payload)
	receipt := pkt.Send()
	if receipt == nil {
		r.log.Warn("Packet send failed",
			"dest", fmt.Sprintf("%x", destHash[:8]),
			"attempt", e.Attempts,
		)
		e.NextAttempt = time.Now().Add(deliveryRetryWait)
		e.State = core.StateOutbound
		return
	}

	r.log.Info("Sent LXMF message (opportunistic)",
		"to", fmt.Sprintf("%x", destHash[:8]),
		"id", e.Message.ID(),
		"len", len(e.Message.Content),
		"attempt", e.Attempts,
	)
	e.State = core.StateSent
	r.emit(&event.DeliveryUpdate{MessageHash: e.Message.Hash, State: core.StateSent})
}

// attemptDirect performs a single direct delivery attempt.
func (r *LXMRouter) attemptDirect(e *outboundEntry) {
	destHash := e.DestHash
	destKey := hex.EncodeToString(destHash)
	msgHash := e.Message.Hash
	msgID := e.Message.ID()
	msgLen := len(e.Message.Content)

	// Reuse an outbound link if available.
	if link := r.getActiveDirectLink(destKey); link != nil {
		r.sendOverLink(link, destHash, e.Packed, msgHash, msgID, msgLen)
		return
	}

	// Establish a new link.
	peerIdentity := rns.IdentityRecall(destHash)
	if peerIdentity == nil {
		r.log.Debug("Peer identity unknown for direct delivery, requesting path",
			"dest", fmt.Sprintf("%x", destHash[:8]),
			"attempt", e.Attempts,
		)
		rns.RequestPath(destHash, nil)
		e.NextAttempt = time.Now().Add(pathRequestWait)
		e.State = core.StateOutbound
		return
	}

	if !rns.HasPath(destHash) {
		rns.RequestPath(destHash, nil)
		e.NextAttempt = time.Now().Add(pathRequestWait)
		e.State = core.StateOutbound
		return
	}

	outDest, err := rns.NewDestination(peerIdentity, rns.DestinationOUT, rns.DestinationSINGLE, core.AppName, core.DeliveryAspect)
	if err != nil {
		e.NextAttempt = time.Now().Add(deliveryRetryWait)
		e.State = core.StateOutbound
		return
	}

	packed := e.Packed
	link, err := rns.NewOutgoingLink(outDest, rns.LinkModeDefault,
		func(l *rns.Link) {
			r.log.Debug("Link established for direct LXMF delivery",
				"to", fmt.Sprintf("%x", destHash[:8]),
				"id", msgID,
			)
			l.Identify(r.identity)
			r.configureLinkCallbacks(l)

			r.linkMu.Lock()
			r.directLinks[destKey] = l
			r.linkMu.Unlock()

			r.sendOverLink(l, destHash, packed, msgHash, msgID, msgLen)
		},
		func(l *rns.Link) {
			r.log.Debug("Direct delivery link closed",
				"to", fmt.Sprintf("%x", destHash[:8]),
				"id", msgID,
			)
			r.removeLinkFromMaps(l)
		},
	)
	if err != nil {
		r.log.Warn("Failed to create outgoing link",
			"dest", fmt.Sprintf("%x", destHash[:8]),
			"error", err,
		)
		e.NextAttempt = time.Now().Add(deliveryRetryWait)
		e.State = core.StateOutbound
		return
	}
	_ = link
}

// getActiveDirectLink returns an active outbound link we initiated. Unlike
// getActiveLink, this does NOT return inbound backchannel links — those are
// controlled by the remote peer and may be torn down at any moment.
func (r *LXMRouter) getActiveDirectLink(destKey string) *rns.Link {
	r.linkMu.Lock()
	defer r.linkMu.Unlock()

	if link, ok := r.directLinks[destKey]; ok && link.Status == rns.LinkActive {
		return link
	}
	return nil
}

// removeLinkFromMaps removes a link from both the backchannel and direct link
// maps when it is closed.
func (r *LXMRouter) removeLinkFromMaps(link *rns.Link) {
	r.linkMu.Lock()
	defer r.linkMu.Unlock()
	for k, l := range r.backchannelLinks {
		if l == link {
			delete(r.backchannelLinks, k)
		}
	}
	for k, l := range r.directLinks {
		if l == link {
			delete(r.directLinks, k)
		}
	}
}

// sendOverLink sends a packed LXMF message over an established link, choosing
// between a link packet (small messages) or a resource transfer (large messages)
// based on the link's MDU.
func (r *LXMRouter) sendOverLink(link *rns.Link, destHash []byte, packed []byte, msgHash []byte, msgID string, msgLen int) {
	if len(packed) <= link.MDU {
		r.sendLinkPacket(link, destHash, packed, msgHash, msgID, msgLen)
	} else {
		r.sendLinkResource(link, destHash, packed, msgHash, msgID, msgLen)
	}
}

// sendLinkPacket sends a small LXMF message as a link packet.
func (r *LXMRouter) sendLinkPacket(link *rns.Link, destHash []byte, packed []byte, msgHash []byte, msgID string, msgLen int) {
	pkt := rns.NewPacket(link, packed)
	receipt := pkt.Send()
	if receipt == nil {
		r.log.Warn("Failed to send LXMF packet over link",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"id", msgID,
		)
		r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateFailed})
		return
	}

	r.log.Info("Sent LXMF message (direct/packet)",
		"to", fmt.Sprintf("%x", destHash[:8]),
		"id", msgID,
		"len", msgLen,
	)
	r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateSent})

	receipt.SetDeliveryCallback(func(pr *rns.PacketReceipt) {
		r.log.Info("LXMF direct delivery confirmed",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"id", msgID,
		)
		r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateDelivered})
	})
	receipt.SetTimeoutCallback(func(pr *rns.PacketReceipt) {
		r.log.Warn("LXMF direct delivery timed out",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"id", msgID,
		)
		r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateFailed})
	})
}

// sendLinkResource sends a large LXMF message as a resource transfer.
func (r *LXMRouter) sendLinkResource(link *rns.Link, destHash []byte, packed []byte, msgHash []byte, msgID string, msgLen int) {
	timeout := resourceTimeout
	_, err := rns.NewResource(
		packed, nil, link, nil, true, false,
		func(res *rns.Resource) {
			if res == nil {
				return
			}
			if res.Status() == rns.ResourceComplete {
				r.log.Info("LXMF resource transfer complete",
					"to", fmt.Sprintf("%x", destHash[:8]),
					"id", msgID,
				)
				r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateDelivered})
			} else {
				r.log.Warn("LXMF resource transfer failed",
					"to", fmt.Sprintf("%x", destHash[:8]),
					"id", msgID,
					"status", res.Status(),
				)
				r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateFailed})
			}
		},
		nil, &timeout,
		0, nil, nil, false, 0,
	)
	if err != nil {
		r.log.Warn("Failed to create LXMF resource transfer",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"id", msgID,
			"error", err,
		)
		r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateFailed})
		return
	}

	r.log.Info("Sent LXMF message (direct/resource)",
		"to", fmt.Sprintf("%x", destHash[:8]),
		"id", msgID,
		"len", msgLen,
	)
	r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateSent})
}

// updateStampCost caches the stamp cost advertised by a peer in their announce.
func (r *LXMRouter) updateStampCost(destHash []byte, cost int) {
	destHex := hex.EncodeToString(destHash)
	r.stampCostsMu.Lock()
	r.stampCosts[destHex] = stampCostEntry{Cost: cost, Updated: time.Now()}
	r.stampCostsMu.Unlock()
}

// getStampCost returns the cached stamp cost for a destination, or 0 if
// unknown or expired.
func (r *LXMRouter) getStampCost(destHex string) int {
	r.stampCostsMu.RLock()
	entry, ok := r.stampCosts[destHex]
	r.stampCostsMu.RUnlock()
	if !ok || time.Since(entry.Updated) > stampCostExpiry {
		return 0
	}
	return entry.Cost
}

// cleanDeliveredIDs removes expired entries from the delivered message cache.
func (r *LXMRouter) cleanDeliveredIDs() {
	r.deliveredMu.Lock()
	defer r.deliveredMu.Unlock()

	now := time.Now()
	for k, t := range r.deliveredIDs {
		if now.Sub(t) > deliveredIDExpiry {
			delete(r.deliveredIDs, k)
		}
	}
}

// OnEvent registers an event handler. Handlers are called synchronously in
// registration order when events are dispatched.
func (r *LXMRouter) OnEvent(fn event.Handler) {
	r.mu.Lock()
	r.handlers = append(r.handlers, fn)
	r.mu.Unlock()
}

// emit dispatches an event to all registered handlers.
func (r *LXMRouter) emit(evt any) {
	r.mu.RLock()
	handlers := r.handlers
	r.mu.RUnlock()
	for _, h := range handlers {
		h(evt)
	}
}

// handlePacket is called by RNS when a packet arrives on our lxmf.delivery
// destination via opportunistic delivery. data is already decrypted.
func (r *LXMRouter) handlePacket(data []byte, pkt *rns.Packet) {
	r.log.Debug("handlePacket called", "data_len", len(data))
	// Inbound opportunistic packets: RNS strips the dest_hash from the wire
	// before calling this callback, so we must re-prepend our own hash to
	// reconstruct the full LXMF wire format for parsing.
	full := make([]byte, 0, core.DestHashSize+len(data))
	full = append(full, r.destination.Hash()...)
	full = append(full, data...)

	msg, err := core.Unpack(full)
	if err != nil {
		r.log.Debug("Failed to parse LXMF packet", "error", err)
		return
	}
	r.dispatchMessage(msg)
}

// handleLinkEstablished is called when a remote peer opens an RNS link to our
// lxmf.delivery destination (DIRECT delivery mode). We configure the link to
// accept LXMF messages sent either as small link packets or as resource transfers,
// and register a remote-identified callback for backchannel link storage.
func (r *LXMRouter) handleLinkEstablished(link *rns.Link) {
	r.log.Debug("Incoming LXMF link established",
		"link", fmt.Sprintf("%x", link.LinkID[:4]),
	)
	r.configureLinkCallbacks(link)

	// When the remote identifies, store the link as a backchannel so we can
	// reuse it for replies instead of opening a new outgoing link.
	link.SetRemoteIdentifiedCallback(r.handleRemoteIdentified)
	link.SetLinkClosedCallback(func(l *rns.Link) {
		r.log.Debug("Inbound LXMF link closed",
			"link", fmt.Sprintf("%x", l.LinkID[:4]),
		)
		r.removeLinkFromMaps(l)
	})
}

// configureLinkCallbacks sets up packet and resource receive callbacks on a
// link. Used for both inbound links and outbound links (to enable bidirectional
// communication on the same link).
func (r *LXMRouter) configureLinkCallbacks(link *rns.Link) {
	link.SetPacketCallback(r.handleLinkPacket)
	_ = link.SetResourceStrategy(rns.LinkAcceptApp)
	link.SetResourceCallback(func(adv *rns.ResourceAdvertisement) bool { return true })
	link.SetResourceConcludedCallback(r.handleResourceConcluded)
}

// handleRemoteIdentified is called when a remote peer identifies themselves on
// an inbound link. We compute their delivery destination hash and store the
// link for backchannel reuse.
func (r *LXMRouter) handleRemoteIdentified(link *rns.Link, identity *rns.Identity) {
	destHash, err := rns.DestinationHashFromNameAndIdentity(deliveryAspectName, identity)
	if err != nil {
		r.log.Debug("Failed to compute dest hash for backchannel link",
			"error", err,
		)
		return
	}
	destKey := hex.EncodeToString(destHash)
	r.linkMu.Lock()
	r.backchannelLinks[destKey] = link
	r.linkMu.Unlock()

	r.log.Debug("Backchannel link available",
		"dest", fmt.Sprintf("%x", destHash[:8]),
		"link", fmt.Sprintf("%x", link.LinkID[:4]),
	)
}

// handleLinkPacket handles an LXMF message delivered as a link packet (DIRECT,
// small message). Unlike opportunistic packets the dest_hash is NOT prepended.
func (r *LXMRouter) handleLinkPacket(data []byte, pkt *rns.Packet) {
	r.log.Debug("handleLinkPacket called", "data_len", len(data))
	msg, err := core.Unpack(data)
	if err != nil {
		r.log.Debug("Failed to parse LXMF link packet", "error", err)
		return
	}
	// Store the link as a backchannel keyed by the sender's source hash so
	// replies can be sent back over the same link immediately, without waiting
	// for the remote to identify or for an announce to arrive.
	if pkt != nil && pkt.Link != nil && pkt.Link.Status == rns.LinkActive {
		r.registerBackchannelFromSource(msg.SourceHash, pkt.Link)
	}
	r.dispatchMessage(msg)
}

// handleResourceConcluded handles an LXMF message delivered as a resource
// transfer (DIRECT, large message). The resource data is read from its storage
// file.
func (r *LXMRouter) handleResourceConcluded(res *rns.Resource) {
	if res.Status() != rns.ResourceComplete {
		return
	}
	path := res.DataFile()
	data, err := os.ReadFile(path)
	if err != nil {
		r.log.Debug("Failed to read LXMF resource file", "path", path, "error", err)
		return
	}
	r.log.Debug("handleResourceConcluded called", "data_len", len(data))
	msg, err := core.Unpack(data)
	if err != nil {
		r.log.Debug("Failed to parse LXMF resource", "error", err)
		return
	}
	// Store the link as a backchannel for replies.
	if link := res.Link(); link != nil && link.Status == rns.LinkActive {
		r.registerBackchannelFromSource(msg.SourceHash, link)
	}
	r.dispatchMessage(msg)
}

// registerBackchannelFromSource stores a link as a backchannel keyed by the
// sender's LXMF source hash. This is called when a message arrives on a DIRECT
// link before the remote has identified, so we can immediately reply over the
// same link.
func (r *LXMRouter) registerBackchannelFromSource(sourceHash []byte, link *rns.Link) {
	destKey := hex.EncodeToString(sourceHash)
	r.linkMu.Lock()
	existing := r.backchannelLinks[destKey]
	if existing == nil || existing.Status != rns.LinkActive {
		r.backchannelLinks[destKey] = link
		r.linkMu.Unlock()
		r.log.Debug("Backchannel link registered from message source",
			"source", fmt.Sprintf("%x", sourceHash[:8]),
			"link", fmt.Sprintf("%x", link.LinkID[:4]),
		)
	} else {
		r.linkMu.Unlock()
	}
}

// dispatchMessage verifies and emits a received LXMF message regardless of
// how it arrived (opportunistic, link packet, or resource transfer).
func (r *LXMRouter) dispatchMessage(msg *core.LXMessage) {
	var srcIdentity *rns.Identity
	var verified bool
	srcIdentity = rns.IdentityRecall(msg.SourceHash)
	if srcIdentity != nil {
		pubBytes := srcIdentity.GetPublicKey()
		if len(pubBytes) >= 64 {
			edPub := ed25519.PublicKey(pubBytes[32:64])
			verified = msg.Verify(edPub)
			if !verified {
				r.log.Warn("LXMF signature verification failed",
					"from", fmt.Sprintf("%x", msg.SourceHash[:8]),
					"id", msg.ID(),
				)
			}
		}
	} else {
		r.log.Debug("Source identity unknown, cannot verify signature",
			"from", fmt.Sprintf("%x", msg.SourceHash[:8]),
		)
	}

	// Duplicate detection: drop messages we've already delivered.
	msgHashHex := hex.EncodeToString(msg.Hash)
	r.deliveredMu.Lock()
	if _, dup := r.deliveredIDs[msgHashHex]; dup {
		r.deliveredMu.Unlock()
		r.log.Debug("Ignoring duplicate message",
			"from", fmt.Sprintf("%x", msg.SourceHash[:8]),
			"id", msg.ID(),
		)
		return
	}
	r.deliveredIDs[msgHashHex] = time.Now()
	r.deliveredMu.Unlock()

	sourceHex := hex.EncodeToString(msg.SourceHash)

	// Remember any ticket the sender included so we can bypass PoW when
	// replying to them.
	if ticketField, ok := msg.Fields[core.FieldTicket]; ok {
		if entry, ok := ticketField.([]any); ok && len(entry) >= 2 {
			if expiresF, ok := entry[0].(float64); ok {
				if ticket, ok := entry[1].([]byte); ok && len(ticket) == core.TicketLength {
					expires := time.Unix(int64(expiresF), 0)
					r.tickets.RememberTicket(sourceHex, expires, ticket)
				}
			}
		}
	}

	// Validate stamp if the router has a stamp cost configured. Pass our
	// inbound tickets for this sender so ticket-based stamps are accepted.
	stampValid := true
	if r.cfg.StampCost > 0 {
		tickets := r.tickets.GetInboundTickets(sourceHex)
		stampValid, _ = core.ValidateStamp(msg, r.cfg.StampCost, tickets)
	}

	if r.cfg.EnforceStamps && !stampValid {
		r.log.Warn("Dropping LXMF message with invalid stamp",
			"from", fmt.Sprintf("%x", msg.SourceHash[:8]),
			"id", msg.ID(),
		)
		return
	}

	r.log.Info("Received LXMF message",
		"from", fmt.Sprintf("%x", msg.SourceHash[:8]),
		"id", msg.ID(),
		"verified", verified,
		"stamp_valid", stampValid,
		"len", len(msg.Content),
	)

	r.emit(&event.MessageReceived{
		Message:        msg,
		SourceIdentity: srcIdentity,
		Verified:       verified,
		StampValid:     stampValid,
	})
}
