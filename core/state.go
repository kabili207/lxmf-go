package core

// State represents the delivery lifecycle of an outbound LXMessage.
type State int

const (
	StateGenerating State = 0x00
	StateOutbound   State = 0x01
	StateSending    State = 0x02
	StateSent       State = 0x04
	StateDelivered  State = 0x08
	StateRejected   State = 0xFD
	StateCancelled  State = 0xFE
	StateFailed     State = 0xFF
)

func (s State) String() string {
	switch s {
	case StateGenerating:
		return "generating"
	case StateOutbound:
		return "outbound"
	case StateSending:
		return "sending"
	case StateSent:
		return "sent"
	case StateDelivered:
		return "delivered"
	case StateRejected:
		return "rejected"
	case StateCancelled:
		return "cancelled"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}
