package core

import (
	"testing"
	"time"
)

func TestTicketStoreGenerateAndRetrieve(t *testing.T) {
	ts := NewTicketStore()

	expires, ticket, ok := ts.GenerateTicket("aabb")
	if !ok {
		t.Fatal("GenerateTicket should succeed")
	}
	if len(ticket) != TicketLength {
		t.Fatalf("ticket length = %d, want %d", len(ticket), TicketLength)
	}
	if expires.Before(time.Now()) {
		t.Error("ticket should not already be expired")
	}

	// Should reuse the same ticket since it has plenty of validity.
	expires2, ticket2, ok2 := ts.GenerateTicket("aabb")
	if !ok2 {
		t.Fatal("second GenerateTicket should succeed (reuse)")
	}
	if string(ticket2) != string(ticket) {
		t.Error("should reuse existing ticket with enough validity")
	}
	if expires2 != expires {
		t.Error("expiry should match for reused ticket")
	}
}

func TestTicketStoreDeliveryInterval(t *testing.T) {
	ts := NewTicketStore()

	_, _, ok := ts.GenerateTicket("aabb")
	if !ok {
		t.Fatal("first GenerateTicket should succeed")
	}

	// Record that we delivered a ticket.
	ts.RecordTicketDelivery("aabb")

	// A second generate within the interval should fail.
	_, _, ok = ts.GenerateTicket("aabb")
	if ok {
		t.Error("GenerateTicket should fail within TicketInterval")
	}
}

func TestTicketStoreOutbound(t *testing.T) {
	ts := NewTicketStore()

	// Nothing stored yet.
	if ts.GetOutboundTicket("ccdd") != nil {
		t.Error("should return nil for unknown destination")
	}

	ticket := []byte("0123456789abcdef")
	expires := time.Now().Add(24 * time.Hour)
	ts.RememberTicket("ccdd", expires, ticket)

	got := ts.GetOutboundTicket("ccdd")
	if got == nil {
		t.Fatal("GetOutboundTicket should return the remembered ticket")
	}
	if string(got) != string(ticket) {
		t.Error("ticket mismatch")
	}

	// Expired ticket should not be returned.
	ts.RememberTicket("eeff", time.Now().Add(-1*time.Hour), ticket)
	if ts.GetOutboundTicket("eeff") != nil {
		t.Error("expired ticket should not be returned")
	}
}

func TestTicketStoreInbound(t *testing.T) {
	ts := NewTicketStore()

	if ts.GetInboundTickets("aabb") != nil {
		t.Error("should return nil for unknown source")
	}

	_, ticket, ok := ts.GenerateTicket("aabb")
	if !ok {
		t.Fatal("GenerateTicket should succeed")
	}

	tickets := ts.GetInboundTickets("aabb")
	if len(tickets) != 1 {
		t.Fatalf("expected 1 inbound ticket, got %d", len(tickets))
	}
	if string(tickets[0]) != string(ticket) {
		t.Error("inbound ticket mismatch")
	}
}

func TestTicketStoreClean(t *testing.T) {
	ts := NewTicketStore()

	// Add an expired outbound ticket.
	ts.RememberTicket("aaaa", time.Now().Add(-1*time.Hour), []byte("expired_ticket!!"))

	// Add an expired inbound ticket (past grace period).
	ts.mu.Lock()
	ts.inbound["bbbb"] = []inboundTicket{{
		Ticket:  []byte("old_ticket______"),
		Expires: time.Now().Add(-TicketGrace - time.Hour),
	}}
	ts.mu.Unlock()

	ts.Clean()

	if ts.GetOutboundTicket("aaaa") != nil {
		t.Error("expired outbound ticket should be cleaned")
	}
	if ts.GetInboundTickets("bbbb") != nil {
		t.Error("expired inbound ticket should be cleaned")
	}
}

func TestTicketStampValidation(t *testing.T) {
	// Test vector from Python: ticket + message_id -> truncated_hash
	ts := NewTicketStore()

	messageHash := mustHex("2d44d28ae7059f42e80b49ae456e4b1d55adfce523a393e1ddfa6e5a90a4cc22")
	ticket := mustHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	expectedStamp := mustHex("6f08e3d7eef2c2deed3165c4b885547e")

	// Store the ticket as an inbound ticket (we generated it for a peer).
	ts.mu.Lock()
	ts.inbound["source_hex"] = []inboundTicket{{
		Ticket:  ticket,
		Expires: time.Now().Add(24 * time.Hour),
	}}
	ts.mu.Unlock()

	tickets := ts.GetInboundTickets("source_hex")
	if len(tickets) != 1 {
		t.Fatal("expected 1 inbound ticket")
	}

	// Build a message with the ticket-based stamp.
	msg := &LXMessage{
		Hash:  messageHash,
		Stamp: expectedStamp,
	}

	valid, value := ValidateStamp(msg, 16, tickets)
	if !valid {
		t.Error("ticket-based stamp should validate")
	}
	if value != CostTicket {
		t.Errorf("value = %d, want CostTicket (%d)", value, CostTicket)
	}
}
