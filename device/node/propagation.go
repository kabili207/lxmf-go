package node

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kabili207/lxmf-go/core"
	"github.com/kabili207/lxmf-go/device/event"
	rns "github.com/svanichkin/go-reticulum/rns"
)

const (
	// prPathTimeout is how long to wait for a path to the propagation node.
	prPathTimeout = 10 * time.Second
)

// SetOutboundPropagationNode configures the propagation node to use for
// downloading messages and (optionally) sending via propagation. Pass nil to
// clear the configured node.
func (r *LXMRouter) SetOutboundPropagationNode(destHash []byte) {
	r.propagationMu.Lock()
	defer r.propagationMu.Unlock()

	// Tear down existing link if switching nodes.
	if r.propagationLink != nil && !bytesEqual(r.propagationNode, destHash) {
		r.propagationLink.Teardown()
		r.propagationLink = nil
	}

	r.propagationNode = destHash
	r.propagationState = core.PRIdle
	r.propagationProgress = 0
}

// PropagationState returns the current propagation transfer state and progress.
func (r *LXMRouter) PropagationState() (core.PropagationTransferState, float64) {
	r.propagationMu.Lock()
	defer r.propagationMu.Unlock()
	return r.propagationState, r.propagationProgress
}

// RequestMessages initiates a message download from the configured propagation
// node. Progress and completion are reported via PropagationSyncUpdate events.
func (r *LXMRouter) RequestMessages() error {
	r.propagationMu.Lock()
	defer r.propagationMu.Unlock()

	if r.propagationNode == nil {
		return fmt.Errorf("no propagation node configured")
	}

	r.propagationProgress = 0

	// If we already have an active link, use it directly.
	if r.propagationLink != nil && r.propagationLink.Status == rns.LinkActive {
		r.propagationState = core.PRLinkEstablished
		r.propagationLink.Identify(r.identity)
		r.sendListRequest(r.propagationLink)
		return nil
	}

	// Need to establish a new link.
	r.propagationLink = nil
	nodeHash := r.propagationNode

	if !rns.HasPath(nodeHash) {
		r.propagationState = core.PRPathRequested
		rns.RequestPath(nodeHash, nil, nil, false)
		r.emitSyncUpdate()

		go r.waitForPropagationPath(nodeHash)
		return nil
	}

	return r.establishPropagationLink(nodeHash)
}

// CancelPropagationNodeRequests tears down the propagation link and resets
// the transfer state.
func (r *LXMRouter) CancelPropagationNodeRequests() {
	r.propagationMu.Lock()
	defer r.propagationMu.Unlock()

	if r.propagationLink != nil {
		r.propagationLink.Teardown()
		r.propagationLink = nil
	}
	r.propagationState = core.PRIdle
	r.propagationProgress = 0
}

// waitForPropagationPath polls for a path to the propagation node, then
// establishes a link. Called in a goroutine.
func (r *LXMRouter) waitForPropagationPath(nodeHash []byte) {
	deadline := time.Now().Add(prPathTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if rns.HasPath(nodeHash) {
			r.propagationMu.Lock()
			// Verify we're still waiting for this node.
			if !bytesEqual(r.propagationNode, nodeHash) || r.propagationState != core.PRPathRequested {
				r.propagationMu.Unlock()
				return
			}
			err := r.establishPropagationLink(nodeHash)
			r.propagationMu.Unlock()
			if err != nil {
				r.log.Warn("Failed to establish propagation link after path found", "error", err)
			}
			return
		}
	}

	r.propagationMu.Lock()
	if bytesEqual(r.propagationNode, nodeHash) && r.propagationState == core.PRPathRequested {
		r.propagationState = core.PRNoPath
		r.emitSyncUpdate()
	}
	r.propagationMu.Unlock()
}

// establishPropagationLink creates an outgoing link to the propagation node.
// Must be called with propagationMu held.
func (r *LXMRouter) establishPropagationLink(nodeHash []byte) error {
	nodeIdentity := rns.IdentityRecall(nodeHash)
	if nodeIdentity == nil {
		r.propagationState = core.PRFailed
		r.emitSyncUpdate()
		return fmt.Errorf("propagation node identity unknown for %x", nodeHash[:8])
	}

	dest, err := rns.NewDestination(nodeIdentity, rns.DestinationOUT, rns.DestinationSINGLE, core.AppName, core.PropagationAspect)
	if err != nil {
		r.propagationState = core.PRFailed
		r.emitSyncUpdate()
		return fmt.Errorf("create propagation destination: %w", err)
	}

	r.propagationState = core.PRLinkEstablishing
	r.emitSyncUpdate()

	link, err := rns.NewLink(dest, nil, rns.LinkModeDefault,
		func(l *rns.Link) {
			r.propagationMu.Lock()
			r.propagationLink = l
			r.propagationState = core.PRLinkEstablished
			r.propagationMu.Unlock()

			l.Identify(r.identity)
			r.sendListRequest(l)
		},
		func(l *rns.Link) {
			r.propagationMu.Lock()
			if r.propagationLink == l {
				r.propagationLink = nil
				if r.propagationState != core.PRComplete {
					r.propagationState = core.PRLinkFailed
					r.emitSyncUpdate()
				}
			}
			r.propagationMu.Unlock()
		},
	)
	if err != nil {
		r.propagationState = core.PRLinkFailed
		r.emitSyncUpdate()
		return fmt.Errorf("create propagation link: %w", err)
	}
	_ = link

	return nil
}

// sendListRequest sends the initial [None, None] request to get the list of
// available messages.
func (r *LXMRouter) sendListRequest(link *rns.Link) {
	r.propagationMu.Lock()
	r.propagationState = core.PRRequestSent
	r.emitSyncUpdate()
	r.propagationMu.Unlock()

	r.log.Debug("Requesting message list from propagation node")
	link.Request(
		core.MessageGetPath,
		[]any{nil, nil},
		r.messageListResponse,
		r.messageGetFailed,
		nil,
		0,
	)
}

// messageListResponse handles the response to the list request.
func (r *LXMRouter) messageListResponse(rr *rns.RequestReceipt) {
	resp := rr.Response()

	// Check for error codes (returned as integers).
	if code, ok := asInt(resp); ok {
		r.propagationMu.Lock()
		switch code {
		case core.PNErrorNoIdentity:
			r.log.Warn("Propagation node: missing identification")
			r.propagationState = core.PRNoIdentityRcvd
		case core.PNErrorNoAccess:
			r.log.Warn("Propagation node: access denied")
			r.propagationState = core.PRNoAccess
		default:
			r.log.Warn("Propagation node: unknown error", "code", code)
			r.propagationState = core.PRFailed
		}
		r.emitSyncUpdate()
		if r.propagationLink != nil {
			r.propagationLink.Teardown()
		}
		r.propagationMu.Unlock()
		return
	}

	transientIDs, ok := resp.([]any)
	if !ok || resp == nil {
		r.log.Debug("Invalid message list response from propagation node")
		r.propagationMu.Lock()
		r.propagationState = core.PRTransferFailed
		r.emitSyncUpdate()
		if r.propagationLink != nil {
			r.propagationLink.Teardown()
		}
		r.propagationMu.Unlock()
		return
	}

	if len(transientIDs) == 0 {
		r.log.Debug("No messages available on propagation node")
		r.propagationMu.Lock()
		r.propagationState = core.PRComplete
		r.propagationProgress = 1.0
		r.emitSyncUpdate()
		r.propagationMu.Unlock()
		return
	}

	// Partition into wants and haves.
	var wants []any
	var haves []any

	r.deliveredMu.Lock()
	for _, raw := range transientIDs {
		tid, ok := raw.([]byte)
		if !ok {
			continue
		}
		tidHex := hex.EncodeToString(tid)
		if _, delivered := r.deliveredIDs[tidHex]; delivered {
			haves = append(haves, tid)
		} else {
			wants = append(wants, tid)
		}
	}
	r.deliveredMu.Unlock()

	if len(wants) == 0 {
		// We already have everything. Send haves to clean up the node, then complete.
		r.log.Debug("All messages already delivered, sending cleanup")
		r.propagationMu.Lock()
		link := r.propagationLink
		r.propagationMu.Unlock()

		if link != nil && link.Status == rns.LinkActive {
			link.Request(core.MessageGetPath, []any{nil, haves}, nil, nil, nil, 0)
		}

		r.propagationMu.Lock()
		r.propagationState = core.PRComplete
		r.propagationProgress = 1.0
		r.emitSyncUpdate()
		r.propagationMu.Unlock()
		return
	}

	r.log.Debug("Requesting messages from propagation node",
		"wants", len(wants),
		"haves", len(haves),
	)

	r.propagationMu.Lock()
	link := r.propagationLink
	limit := r.cfg.DeliveryLimit
	if limit == 0 {
		limit = 1000
	}
	r.propagationMu.Unlock()

	if link != nil && link.Status == rns.LinkActive {
		link.Request(
			core.MessageGetPath,
			[]any{wants, haves, limit},
			r.messageGetResponse,
			r.messageGetFailed,
			r.messageGetProgress,
			0,
		)
	}
}

// messageGetResponse handles the response containing actual message data.
func (r *LXMRouter) messageGetResponse(rr *rns.RequestReceipt) {
	resp := rr.Response()

	// Check for error codes.
	if code, ok := asInt(resp); ok {
		r.propagationMu.Lock()
		switch code {
		case core.PNErrorNoIdentity:
			r.propagationState = core.PRNoIdentityRcvd
		case core.PNErrorNoAccess:
			r.propagationState = core.PRNoAccess
		default:
			r.propagationState = core.PRFailed
		}
		r.emitSyncUpdate()
		if r.propagationLink != nil {
			r.propagationLink.Teardown()
		}
		r.propagationMu.Unlock()
		return
	}

	messages, ok := resp.([]any)
	if !ok || resp == nil {
		r.propagationMu.Lock()
		r.propagationState = core.PRTransferFailed
		r.emitSyncUpdate()
		r.propagationMu.Unlock()
		return
	}

	var haves []any
	delivered := 0

	for _, raw := range messages {
		lxmfData, ok := raw.([]byte)
		if !ok || len(lxmfData) <= core.DestHashSize {
			continue
		}

		// Track for cleanup acknowledgment.
		h := sha256.Sum256(lxmfData)
		haves = append(haves, h[:])

		// Decrypt: the data is dest_hash(16) + encrypted_rest.
		encryptedRest := lxmfData[core.DestHashSize:]
		decrypted := r.destination.Decrypt(encryptedRest)
		if decrypted == nil {
			r.log.Debug("Failed to decrypt propagated message")
			continue
		}

		// Reconstruct the full packed message: dest_hash + decrypted.
		fullPacked := make([]byte, 0, core.DestHashSize+len(decrypted))
		fullPacked = append(fullPacked, lxmfData[:core.DestHashSize]...)
		fullPacked = append(fullPacked, decrypted...)

		msg, err := core.Unpack(fullPacked)
		if err != nil {
			r.log.Debug("Failed to unpack propagated message", "error", err)
			continue
		}

		// Track the transient_id as delivered.
		transientID := h[:]
		tidHex := hex.EncodeToString(transientID)
		r.deliveredMu.Lock()
		r.deliveredIDs[tidHex] = time.Now()
		r.deliveredMu.Unlock()

		r.dispatchMessage(msg)
		delivered++
	}

	// Send cleanup request to tell the node we received these.
	r.propagationMu.Lock()
	link := r.propagationLink
	r.propagationMu.Unlock()

	if len(haves) > 0 && link != nil && link.Status == rns.LinkActive {
		link.Request(core.MessageGetPath, []any{nil, haves}, nil, nil, nil, 0)
	}

	r.propagationMu.Lock()
	r.propagationState = core.PRComplete
	r.propagationProgress = 1.0
	r.propagationMu.Unlock()

	r.log.Info("Propagation sync complete", "messages", delivered)
	r.emit(&event.PropagationSyncUpdate{
		State:    core.PRComplete,
		Progress: 1.0,
		Messages: delivered,
	})
}

// messageGetProgress updates the transfer progress during download.
func (r *LXMRouter) messageGetProgress(rr *rns.RequestReceipt) {
	r.propagationMu.Lock()
	r.propagationState = core.PRReceiving
	r.propagationProgress = rr.Progress()
	r.propagationMu.Unlock()

	r.emit(&event.PropagationSyncUpdate{
		State:    core.PRReceiving,
		Progress: rr.Progress(),
	})
}

// messageGetFailed handles request failure for both list and get requests.
func (r *LXMRouter) messageGetFailed(rr *rns.RequestReceipt) {
	r.log.Debug("Propagation message request failed")
	r.propagationMu.Lock()
	r.propagationState = core.PRTransferFailed
	if r.propagationLink != nil {
		r.propagationLink.Teardown()
		r.propagationLink = nil
	}
	r.propagationMu.Unlock()

	r.emit(&event.PropagationSyncUpdate{
		State: core.PRTransferFailed,
	})
}

// emitSyncUpdate emits a PropagationSyncUpdate with the current state.
// Must be called with propagationMu held (reads state and progress).
func (r *LXMRouter) emitSyncUpdate() {
	r.emit(&event.PropagationSyncUpdate{
		State:    r.propagationState,
		Progress: r.propagationProgress,
	})
}

// attemptPropagated sends a message via the configured propagation node.
func (r *LXMRouter) attemptPropagated(e *outboundEntry) {
	r.propagationMu.Lock()
	nodeHash := r.propagationNode
	link := r.propagationLink
	r.propagationMu.Unlock()

	if nodeHash == nil {
		r.log.Warn("No propagation node configured, failing message",
			"id", e.Message.ID(),
		)
		e.State = core.StateFailed
		r.emit(&event.DeliveryUpdate{MessageHash: e.Message.Hash, State: core.StateFailed})
		return
	}

	if e.PropagationPacked == nil {
		r.log.Warn("Missing propagation-packed data", "id", e.Message.ID())
		e.State = core.StateFailed
		r.emit(&event.DeliveryUpdate{MessageHash: e.Message.Hash, State: core.StateFailed})
		return
	}

	// If we have an active link to the PN, send immediately.
	if link != nil && link.Status == rns.LinkActive {
		r.sendPropagatedOverLink(link, e)
		return
	}

	// Need to establish a link to the PN first.
	if !rns.HasPath(nodeHash) {
		rns.RequestPath(nodeHash, nil, nil, false)
		e.NextAttempt = time.Now().Add(pathRequestWait)
		e.State = core.StateOutbound
		return
	}

	nodeIdentity := rns.IdentityRecall(nodeHash)
	if nodeIdentity == nil {
		e.NextAttempt = time.Now().Add(pathRequestWait)
		e.State = core.StateOutbound
		return
	}

	dest, err := rns.NewDestination(nodeIdentity, rns.DestinationOUT, rns.DestinationSINGLE, core.AppName, core.PropagationAspect)
	if err != nil {
		e.NextAttempt = time.Now().Add(deliveryRetryWait)
		e.State = core.StateOutbound
		return
	}

	msgHash := e.Message.Hash
	msgID := e.Message.ID()
	propagationPacked := e.PropagationPacked

	_, err = rns.NewLink(dest, nil, rns.LinkModeDefault,
		func(l *rns.Link) {
			r.propagationMu.Lock()
			r.propagationLink = l
			r.propagationMu.Unlock()

			l.Identify(r.identity)

			// Find the entry and send. The entry may still be in the queue.
			r.outbound.mu.Lock()
			for _, oe := range r.outbound.entries {
				if bytesEqual(oe.Message.Hash, msgHash) {
					r.outbound.mu.Unlock()
					r.sendPropagatedOverLink(l, oe)
					return
				}
			}
			r.outbound.mu.Unlock()

			r.log.Debug("Propagation link established but entry no longer in queue",
				"id", msgID,
			)
		},
		func(l *rns.Link) {
			r.propagationMu.Lock()
			if r.propagationLink == l {
				r.propagationLink = nil
			}
			r.propagationMu.Unlock()
		},
	)
	if err != nil {
		e.NextAttempt = time.Now().Add(deliveryRetryWait)
		e.State = core.StateOutbound
		return
	}
	_ = propagationPacked // captured by closure above via entry lookup
}

// sendPropagatedOverLink sends the propagation-packed message over a link to
// the propagation node.
func (r *LXMRouter) sendPropagatedOverLink(link *rns.Link, e *outboundEntry) {
	destHash := e.DestHash
	msgHash := e.Message.Hash
	msgID := e.Message.ID()
	data := e.PropagationPacked

	if len(data) <= link.MDU {
		pkt := rns.NewPacket(link, data)
		receipt := pkt.Send()
		if receipt == nil {
			e.NextAttempt = time.Now().Add(deliveryRetryWait)
			e.State = core.StateOutbound
			return
		}

		r.log.Info("Sent LXMF message (propagated/packet)",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"id", msgID,
		)
		e.State = core.StateSent
		r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateSent})

		receipt.SetDeliveryCallback(func(pr *rns.PacketReceipt) {
			r.outbound.markState(msgHash, core.StateSent)
			r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateSent})
		})
		receipt.SetTimeoutCallback(func(pr *rns.PacketReceipt) {
			r.log.Warn("Propagated delivery timed out", "id", msgID)
			r.outbound.markState(msgHash, core.StateFailed)
			r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateFailed})
		})
	} else {
		timeout := resourceTimeout
		_, err := rns.NewResource(
			data, nil, link, nil, true, false,
			func(res *rns.Resource) {
				if res != nil && res.Status() == rns.ResourceComplete {
					r.log.Info("Propagated resource transfer complete", "id", msgID)
					r.outbound.markState(msgHash, core.StateSent)
					r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateSent})
				} else {
					r.log.Warn("Propagated resource transfer failed", "id", msgID)
					r.outbound.markState(msgHash, core.StateFailed)
					r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateFailed})
				}
			},
			nil, &timeout,
			0, nil, nil, false, 0,
		)
		if err != nil {
			e.NextAttempt = time.Now().Add(deliveryRetryWait)
			e.State = core.StateOutbound
			return
		}

		r.log.Info("Sent LXMF message (propagated/resource)",
			"to", fmt.Sprintf("%x", destHash[:8]),
			"id", msgID,
		)
		e.State = core.StateSending
		r.emit(&event.DeliveryUpdate{MessageHash: msgHash, State: core.StateSending})
	}
}

// asInt attempts to extract an integer from a msgpack-deserialized value.
// The go msgpack library may return int8, int16, int32, int64, uint8, etc.
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		return int(n), true
	default:
		return 0, false
	}
}
