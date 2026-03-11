// Package node provides the LXMRouter, the primary entrypoint for sending
// and receiving LXMF messages over a Reticulum network.
package node

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kabili207/lxmf-go/core"
	"github.com/kabili207/lxmf-go/device/event"
	rns "github.com/svanichkin/go-reticulum/rns"
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
}

// NewRouter creates a new LXMRouter. Call Start to begin processing.
func NewRouter(cfg RouterConfig) (*LXMRouter, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default().With("component", "lxmf")
	}

	return &LXMRouter{
		cfg: cfg,
		log: log,
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

	// Register announce handler for peer discovery.
	rns.RegisterAnnounceHandler(&deliveryAnnounceHandler{router: r})

	r.log.Info("LXMF router started",
		"hash", fmt.Sprintf("%x", dest.Hash()),
		"name", r.cfg.DisplayName,
	)
	return nil
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

// Send delivers an outbound LXMessage to the destination identified by
// destHash (16-byte RNS truncated hash). The message is signed with this
// node's Ed25519 key before sending.
func (r *LXMRouter) Send(destHash []byte, msg *core.LXMessage) error {
	if r.destination == nil {
		return fmt.Errorf("router not started")
	}

	msg.SourceHash = r.destination.Hash()
	msg.DestinationHash = destHash

	if err := msg.Sign(r.privKey); err != nil {
		return fmt.Errorf("sign message: %w", err)
	}

	packed, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("pack message: %w", err)
	}

	// Build the outbound RNS destination (OUT/SINGLE to peer's lxmf.delivery).
	// For opportunistic delivery, the destination hash is already in the packet
	// header added by RNS, so we send the payload without the first 16 bytes.
	peerIdentity := rns.IdentityRecall(destHash)
	if peerIdentity == nil {
		// We don't know the identity yet — request path and send opportunistically.
		// The peer must have announced recently for this to succeed.
		r.log.Warn("Peer identity unknown; path may not exist", "dest", fmt.Sprintf("%x", destHash))
	}

	outDest, err := rns.NewDestination(peerIdentity, rns.DestinationOUT, rns.DestinationSINGLE, core.AppName, core.DeliveryAspect)
	if err != nil {
		return fmt.Errorf("create outbound destination: %w", err)
	}

	// Opportunistic delivery: strip dest_hash prefix (RNS adds it in the
	// packet header) and send the remainder as packet data.
	payload := packed[core.DestHashSize:]
	pkt := rns.NewPacket(outDest, payload)
	pkt.Send()

	r.log.Info("Sent LXMF message",
		"to", fmt.Sprintf("%x", destHash[:8]),
		"id", msg.ID(),
		"len", len(msg.Content),
	)
	r.emit(&event.DeliveryUpdate{MessageHash: msg.Hash, State: core.StateSent})
	return nil
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
// destination. data is already decrypted.
func (r *LXMRouter) handlePacket(data []byte, pkt *rns.Packet) {
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

	// Recall the source identity to verify the signature.
	var srcIdentity *rns.Identity
	var verified bool
	srcIdentity = rns.IdentityRecall(msg.SourceHash)
	if srcIdentity != nil {
		pubBytes := srcIdentity.GetPublicKey()
		// GetPublicKey() returns [32-byte X25519 pub || 32-byte Ed25519 pub].
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

	r.log.Info("Received LXMF message",
		"from", fmt.Sprintf("%x", msg.SourceHash[:8]),
		"id", msg.ID(),
		"verified", verified,
		"len", len(msg.Content),
	)

	r.emit(&event.MessageReceived{
		Message:        msg,
		SourceIdentity: srcIdentity,
		Verified:       verified,
	})
}
