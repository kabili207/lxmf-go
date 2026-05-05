package node

import (
	"fmt"

	"github.com/kabili207/lxmf-go/core"
	"github.com/kabili207/lxmf-go/device/event"
	"github.com/vmihailenco/msgpack/v5"
	rns "github.com/svanichkin/go-reticulum/rns"
)

// deliveryAnnounceHandler implements rns.AnnounceHandler for lxmf.delivery.
type deliveryAnnounceHandler struct {
	router *LXMRouter
}

func (h *deliveryAnnounceHandler) AspectFilter() any {
	return "lxmf.delivery"
}

func (h *deliveryAnnounceHandler) ReceivedAnnounce(destHash []byte, identity *rns.Identity, appData []byte) {
	displayName, stampCost := decodeAnnounceAppData(appData)

	h.router.log.Debug("Received lxmf.delivery announce",
		"from", fmt.Sprintf("%x", destHash[:8]),
		"name", displayName,
		"stamp_cost", stampCost,
	)

	h.router.updateStampCost(destHash, stampCost)

	h.router.emit(&event.PeerAnnounced{
		DestinationHash: destHash,
		Identity:        identity,
		DisplayName:     displayName,
		StampCost:       stampCost,
	})
}

// propagationAnnounceHandler implements rns.AnnounceHandler for lxmf.propagation.
type propagationAnnounceHandler struct {
	router *LXMRouter
}

func (h *propagationAnnounceHandler) AspectFilter() any {
	return core.AppName + "." + core.PropagationAspect
}

func (h *propagationAnnounceHandler) ReceivedAnnounce(destHash []byte, identity *rns.Identity, appData []byte) {
	info := decodePropagationAnnounceAppData(appData)
	if info == nil {
		return
	}

	h.router.log.Debug("Received lxmf.propagation announce",
		"from", fmt.Sprintf("%x", destHash[:8]),
		"enabled", info.Enabled,
		"stamp_cost", info.StampCost,
	)

	h.router.emit(&event.PropagationNodeAnnounced{
		DestinationHash: destHash,
		Identity:        identity,
		Enabled:         info.Enabled,
		TransferLimit:   info.TransferLimit,
		SyncLimit:       info.SyncLimit,
		StampCost:       info.StampCost,
		Timebase:        info.Timebase,
	})
}

// propagationAnnounceInfo holds decoded propagation node announce data.
type propagationAnnounceInfo struct {
	Enabled       bool
	Timebase      int
	TransferLimit int
	SyncLimit     int
	StampCost     int
}

// decodePropagationAnnounceAppData decodes the 7-element msgpack array from a
// propagation node announce:
//
//	[0] = false              (legacy flag)
//	[1] = int(time.time())   (node timebase)
//	[2] = bool               (propagation enabled)
//	[3] = int                (per-transfer limit KB)
//	[4] = int                (per-sync limit KB)
//	[5] = [cost, flex, peering_cost]
//	[6] = {metadata}
func decodePropagationAnnounceAppData(data []byte) *propagationAnnounceInfo {
	if len(data) == 0 {
		return nil
	}

	var parts []msgpack.RawMessage
	if err := msgpack.Unmarshal(data, &parts); err != nil || len(parts) < 3 {
		return nil
	}

	info := &propagationAnnounceInfo{}

	// [1] timebase
	if len(parts) >= 2 {
		var tb int
		if err := msgpack.Unmarshal(parts[1], &tb); err == nil {
			info.Timebase = tb
		}
	}

	// [2] enabled
	if len(parts) >= 3 {
		var enabled bool
		if err := msgpack.Unmarshal(parts[2], &enabled); err == nil {
			info.Enabled = enabled
		}
	}

	// [3] transfer limit
	if len(parts) >= 4 {
		var limit int
		if err := msgpack.Unmarshal(parts[3], &limit); err == nil {
			info.TransferLimit = limit
		}
	}

	// [4] sync limit
	if len(parts) >= 5 {
		var limit int
		if err := msgpack.Unmarshal(parts[4], &limit); err == nil {
			info.SyncLimit = limit
		}
	}

	// [5] stamp costs [cost, flex, peering_cost]
	if len(parts) >= 6 {
		var costs []msgpack.RawMessage
		if err := msgpack.Unmarshal(parts[5], &costs); err == nil && len(costs) >= 1 {
			var cost int
			if err := msgpack.Unmarshal(costs[0], &cost); err == nil {
				info.StampCost = cost
			}
		}
	}

	return info
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
