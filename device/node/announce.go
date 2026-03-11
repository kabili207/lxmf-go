package node

import (
	"fmt"

	"github.com/kabili207/lxmf-go/device/event"
	"github.com/vmihailenco/msgpack/v5"
	rns "github.com/svanichkin/go-reticulum/rns"
)

// deliveryAnnounceHandler implements rns.AnnounceHandler for lxmf.delivery.
type deliveryAnnounceHandler struct {
	router *LXMRouter
}

func (h *deliveryAnnounceHandler) AspectFilter() string {
	return "lxmf.delivery"
}

func (h *deliveryAnnounceHandler) ReceivedAnnounce(destHash []byte, identity *rns.Identity, appData []byte) {
	displayName, stampCost := decodeAnnounceAppData(appData)

	h.router.log.Debug("Received lxmf.delivery announce",
		"from", fmt.Sprintf("%x", destHash[:8]),
		"name", displayName,
		"stamp_cost", stampCost,
	)

	h.router.emit(&event.PeerAnnounced{
		DestinationHash: destHash,
		Identity:        identity,
		DisplayName:     displayName,
		StampCost:       stampCost,
	})
}

// encodeAnnounceAppData encodes the announce app_data for an lxmf.delivery
// destination in the v0.5.0+ format: msgpack([display_name_bytes, stamp_cost]).
// stampCost 0 encodes as nil (no stamp required).
func encodeAnnounceAppData(displayName string, stampCost int) ([]byte, error) {
	var name any
	if displayName != "" {
		name = []byte(displayName)
	}
	var cost any
	if stampCost > 0 {
		cost = stampCost
	}
	return msgpack.Marshal([]any{name, cost})
}

// decodeAnnounceAppData decodes announce app_data. Handles both the v0.5.0+
// msgpack format ([name, stamp_cost]) and the legacy raw UTF-8 name format.
func decodeAnnounceAppData(data []byte) (displayName string, stampCost int) {
	if len(data) == 0 {
		return "", 0
	}

	// Try msgpack array format first.
	var parts []msgpack.RawMessage
	if err := msgpack.Unmarshal(data, &parts); err == nil && len(parts) >= 1 {
		var nameBytes []byte
		if err := msgpack.Unmarshal(parts[0], &nameBytes); err == nil {
			displayName = string(nameBytes)
		}
		if len(parts) >= 2 {
			var cost int
			if err := msgpack.Unmarshal(parts[1], &cost); err == nil {
				stampCost = cost
			}
		}
		return displayName, stampCost
	}

	// Legacy format: raw UTF-8 display name.
	return string(data), 0
}
