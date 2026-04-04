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

	// linkMu protects the backchannel and direct link maps.
	linkMu           sync.Mutex
	backchannelLinks map[string]*rns.Link // hex(destHash) → inbound link (peer identified)
	directLinks      map[string]*rns.Link // hex(destHash) → outbound link we initiated
}

// NewRouter creates a new LXMRouter. Call Start to begin processing.
func NewRouter(cfg RouterConfig) (*LXMRouter, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default().With("component", "lxmf")
	}

	return &LXMRouter{
		cfg:              cfg,
		log:              log,
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
	return nil
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

// Send delivers an outbound LXMessage using the specified delivery method.
// The message is signed with this node's Ed25519 key before sending.
//
// For DeliveryOpportunistic, a single packet is sent with no confirmation.
// For DeliveryDirect, an RNS link is established first; a DeliveryUpdate
// event is emitted when the remote peer's proof is received or when the
// attempt times out.
func (r *LXMRouter) Send(destHash []byte, msg *core.LXMessage, method DeliveryMethod) error {
	if r.destination == nil {
		return fmt.Errorf("router not started")
	}

	msg.SourceHash = r.destination.Hash()
	msg.DestinationHash = destHash

	if err := msg.Sign(context.Background(), r.privKey); err != nil {
		return fmt.Errorf("sign message: %w", err)
	}

	packed, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("pack message: %w", err)
	}

	// Auto-escalate to DIRECT delivery if the packed message exceeds the
	// encrypted packet MDU. Opportunistic delivery to a SINGLE destination
	// encrypts the payload, which limits it to PacketEncryptedMDU (383 bytes
	// at the default 500-byte MTU). Larger messages must go over a link.
	if method == DeliveryOpportunistic && len(packed)-core.DestHashSize > rns.PacketEncryptedMDU {
		r.log.Debug("Message too large for opportunistic delivery, escalating to direct",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"payload", len(packed)-core.DestHashSize,
			"encrypted_mdu", rns.PacketEncryptedMDU,
		)
		method = DeliveryDirect
	}

	switch method {
	case DeliveryDirect:
		return r.sendDirect(destHash, msg, packed)
	default:
		return r.sendOpportunistic(destHash, msg, packed)
	}
}

// sendOpportunistic sends a single best-effort packet to the destination.
// Only reuses outbound links we initiated (directLinks). Inbound backchannel
// links are NOT reused because the remote peer controls their lifecycle and
// may tear them down immediately after sending — replies sent over a dying
// link are silently lost.
func (r *LXMRouter) sendOpportunistic(destHash []byte, msg *core.LXMessage, packed []byte) error {
	destKey := hex.EncodeToString(destHash)

	// Only reuse links we initiated — we control their lifecycle.
	if link := r.getActiveDirectLink(destKey); link != nil {
		r.log.Debug("Sending reply over existing outbound link",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"id", msg.ID(),
		)
		r.sendOverLink(link, destHash, packed, msg.Hash, msg.ID(), len(msg.Content))
		return nil
	}

	peerIdentity := rns.IdentityRecall(destHash)
	if peerIdentity == nil {
		r.log.Warn("Peer identity unknown, requesting path", "dest", fmt.Sprintf("%x", destHash))
		rns.RequestPath(destHash, nil)
		return fmt.Errorf("peer identity unknown for %x; path request sent", destHash[:8])
	}

	// Ensure we have a path before sending. If not, request one and wait
	// briefly — the path table is populated from announces which may not have
	// arrived yet when the router first starts.
	if !rns.HasPath(destHash) {
		r.log.Debug("No path yet, requesting", "dest", fmt.Sprintf("%x", destHash[:8]))
		rns.RequestPath(destHash, nil)
		for i := 0; i < 10; i++ {
			time.Sleep(200 * time.Millisecond)
			if rns.HasPath(destHash) {
				break
			}
		}
		if !rns.HasPath(destHash) {
			return fmt.Errorf("no path to %x after request; will retry on announce", destHash[:8])
		}
	}

	outDest, err := rns.NewDestination(peerIdentity, rns.DestinationOUT, rns.DestinationSINGLE, core.AppName, core.DeliveryAspect)
	if err != nil {
		return fmt.Errorf("create outbound destination: %w", err)
	}

	// Strip dest_hash prefix — RNS encodes it in the packet header.
	payload := packed[core.DestHashSize:]
	pkt := rns.NewPacket(outDest, payload)
	receipt := pkt.Send()
	if receipt == nil {
		return fmt.Errorf("packet send failed for %x (no interfaces or path)", destHash[:8])
	}

	r.log.Info("Sent LXMF message (opportunistic)",
		"to", fmt.Sprintf("%x", destHash[:8]),
		"id", msg.ID(),
		"len", len(msg.Content),
	)
	r.emit(&event.DeliveryUpdate{MessageHash: msg.Hash, State: core.StateSent})
	return nil
}

// sendDirect sends the message over an RNS link — reusing a backchannel or
// direct link if one is already active, or establishing a new link otherwise.
// Small messages are sent as link packets; large messages use resource transfers.
// A DeliveryUpdate is emitted asynchronously on delivery confirmation or timeout.
func (r *LXMRouter) sendDirect(destHash []byte, msg *core.LXMessage, packed []byte) error {
	destKey := hex.EncodeToString(destHash)
	msgHash := msg.Hash
	msgID := msg.ID()
	msgLen := len(msg.Content)

	// Only reuse outbound links we initiated — backchannel (inbound) links are
	// controlled by the remote peer and may be torn down at any moment.
	if link := r.getActiveDirectLink(destKey); link != nil {
		r.log.Debug("Reusing existing outbound link for direct delivery",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"id", msgID,
		)
		r.sendOverLink(link, destHash, packed, msgHash, msgID, msgLen)
		return nil
	}

	// No reusable link — establish a new outgoing link.
	peerIdentity := rns.IdentityRecall(destHash)
	if peerIdentity == nil {
		r.log.Warn("Peer identity unknown for direct delivery; attempting path request", "dest", fmt.Sprintf("%x", destHash))
	}

	outDest, err := rns.NewDestination(peerIdentity, rns.DestinationOUT, rns.DestinationSINGLE, core.AppName, core.DeliveryAspect)
	if err != nil {
		return fmt.Errorf("create outbound destination for direct delivery: %w", err)
	}

	link, err := rns.NewOutgoingLink(outDest, rns.LinkModeDefault,
		func(l *rns.Link) {
			r.log.Debug("Link established for direct LXMF delivery",
				"to", fmt.Sprintf("%x", destHash[:8]),
				"id", msgID,
			)

			// Identify ourselves so the remote can store us as a backchannel.
			l.Identify(r.identity)

			// Set up receive callbacks so we can accept messages on this
			// link too (enables bidirectional communication).
			r.configureLinkCallbacks(l)

			// Store in directLinks for reuse.
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
		return fmt.Errorf("create outgoing link: %w", err)
	}
	_ = link // link lifecycle managed via callbacks above

	return nil
}

// getActiveLink returns a reusable active link for the given destination key,
// checking backchannel links first, then direct links.
func (r *LXMRouter) getActiveLink(destKey string) *rns.Link {
	r.linkMu.Lock()
	defer r.linkMu.Unlock()

	if link, ok := r.backchannelLinks[destKey]; ok && link.Status == rns.LinkActive {
		return link
	}
	if link, ok := r.directLinks[destKey]; ok && link.Status == rns.LinkActive {
		return link
	}

	// Clean up stale entries while we're here.
	for k, l := range r.backchannelLinks {
		if l.Status != rns.LinkActive {
			delete(r.backchannelLinks, k)
		}
	}
	for k, l := range r.directLinks {
		if l.Status != rns.LinkActive {
			delete(r.directLinks, k)
		}
	}
	return nil
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

	// Validate stamp if the router has a stamp cost configured.
	stampValid := true
	if r.cfg.StampCost > 0 {
		stampValid, _ = core.ValidateStamp(msg, r.cfg.StampCost, nil)
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
