package event

import (
	"github.com/kabili207/lxmf-go/core"
	rns "github.com/svanichkin/go-reticulum/rns"
)

// Handler is a callback that receives typed LXMF events.
// Consumers type-switch on the concrete event type:
//
//	router.OnEvent(func(evt any) {
//	    switch e := evt.(type) {
//	    case *event.MessageReceived:
//	        // handle inbound message
//	    case *event.PeerAnnounced:
//	        // handle peer discovery
//	    }
//	})
type Handler func(evt any)

// MessageReceived is emitted when a validated inbound LXMF message arrives.
type MessageReceived struct {
	// Message is the fully parsed and signature-verified LXMF message.
	Message *core.LXMessage

	// SourceIdentity is the sender's RNS Identity (nil if not known/unverifiable).
	SourceIdentity *rns.Identity

	// Verified is true if the Ed25519 signature checked out.
	// Messages that fail verification still emit this event with Verified=false
	// so callers can decide how to handle them (log, drop, quarantine).
	Verified bool

	// StampValid is true if the message's stamp or ticket was validated
	// successfully (or if the router does not require stamps).
	StampValid bool
}

// PeerAnnounced is emitted when an lxmf.delivery announce is received from
// another node. Use this to discover peers and track their display names.
type PeerAnnounced struct {
	// DestinationHash is the 16-byte RNS truncated hash of the peer's
	// lxmf.delivery destination.
	DestinationHash []byte

	// Identity is the peer's announced RNS Identity.
	Identity *rns.Identity

	// DisplayName is the UTF-8 display name from the announce app_data,
	// or "" if none was provided.
	DisplayName string

	// StampCost is the PoW cost required by this peer (0 = none required).
	StampCost int
}

// DeliveryUpdate is emitted when the delivery state of an outbound message
// changes (sent, delivered, failed).
type DeliveryUpdate struct {
	// MessageHash is the 32-byte SHA-256 hash identifying the message.
	MessageHash []byte

	// State is the new delivery state.
	State core.State
}
