package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	// DestHashSize is the size of an RNS truncated destination hash in bytes.
	DestHashSize = 16

	// SigSize is the size of an Ed25519 signature in bytes.
	SigSize = 64

	// HeaderSize is the fixed header size: dest_hash + src_hash + signature.
	HeaderSize = DestHashSize + DestHashSize + SigSize

	// AppName is the LXMF application name used for destination aspects.
	AppName = "lxmf"

	// DeliveryAspect is the destination aspect for LXMF message delivery.
	DeliveryAspect = "delivery"
)

// LXMessage represents a single LXMF message.
type LXMessage struct {
	// Addressing
	DestinationHash []byte // 16-byte RNS truncated hash of recipient's delivery destination
	SourceHash      []byte // 16-byte RNS truncated hash of sender's delivery destination

	// Content
	Timestamp time.Time
	Title     []byte
	Content   []byte
	Fields    map[any]any // int key → value (msgpack dict)

	// Derived on unpack / set on sign
	Signature []byte // 64-byte Ed25519 signature
	Hash      []byte // 32-byte SHA-256 message ID (not on wire; derived)
}

// New creates an outbound LXMessage from the sender's delivery destination hash.
func New(srcHash, destHash []byte, content string) *LXMessage {
	return &LXMessage{
		DestinationHash: destHash,
		SourceHash:      srcHash,
		Timestamp:       time.Now(),
		Content:         []byte(content),
		Fields:          make(map[any]any),
	}
}

// computeHash computes the message ID (SHA-256 of header + packed payload).
// This matches the Python LXMessage.get_hash() implementation.
func (m *LXMessage) computeHash(packedPayload []byte) []byte {
	h := sha256.New()
	h.Write(m.DestinationHash)
	h.Write(m.SourceHash)
	h.Write(packedPayload)
	return h.Sum(nil)
}

// packPayload encodes the [timestamp, title, content, fields] msgpack array.
func (m *LXMessage) packPayload() ([]byte, error) {
	// Encode timestamp as float64 seconds (matches Python's time.time())
	ts := float64(m.Timestamp.UnixNano()) / 1e9

	title := m.Title
	if title == nil {
		title = []byte{}
	}
	content := m.Content
	if content == nil {
		content = []byte{}
	}
	fields := m.Fields
	if fields == nil {
		fields = make(map[any]any)
	}

	return msgpack.Marshal([]any{ts, title, content, fields})
}

// Sign computes the message hash and signs the message with the given Ed25519
// private key (the source identity's signing key). Must be called before Pack.
func (m *LXMessage) Sign(privKey ed25519.PrivateKey) error {
	payload, err := m.packPayload()
	if err != nil {
		return fmt.Errorf("pack payload for signing: %w", err)
	}

	hash := m.computeHash(payload)
	m.Hash = hash

	// signed_part = dest_hash + src_hash + payload + message_hash
	signed := make([]byte, 0, HeaderSize+len(payload)+len(hash))
	signed = append(signed, m.DestinationHash...)
	signed = append(signed, m.SourceHash...)
	signed = append(signed, payload...)
	signed = append(signed, hash...)

	m.Signature = ed25519.Sign(privKey, signed)
	return nil
}

// Pack serializes the message to the LXMF wire format:
//
//	dest_hash(16) + src_hash(16) + signature(64) + msgpack_payload
//
// Sign must be called first.
func (m *LXMessage) Pack() ([]byte, error) {
	if len(m.Signature) != SigSize {
		return nil, fmt.Errorf("message not signed (call Sign first)")
	}
	if len(m.DestinationHash) != DestHashSize || len(m.SourceHash) != DestHashSize {
		return nil, fmt.Errorf("destination or source hash has wrong length")
	}

	payload, err := m.packPayload()
	if err != nil {
		return nil, fmt.Errorf("pack payload: %w", err)
	}

	out := make([]byte, 0, HeaderSize+len(payload))
	out = append(out, m.DestinationHash...)
	out = append(out, m.SourceHash...)
	out = append(out, m.Signature...)
	out = append(out, payload...)
	return out, nil
}

// Unpack parses an inbound LXMF wire-format message. It does not verify the
// signature — call Verify after obtaining the source identity's public key.
func Unpack(data []byte) (*LXMessage, error) {
	if len(data) < HeaderSize+1 {
		return nil, fmt.Errorf("message too short: %d bytes", len(data))
	}

	m := &LXMessage{
		DestinationHash: data[:DestHashSize],
		SourceHash:      data[DestHashSize : DestHashSize*2],
		Signature:       data[DestHashSize*2 : HeaderSize],
	}

	payload := data[HeaderSize:]

	// Decode [timestamp_float64, title_bytes, content_bytes, fields_dict]
	var parts []msgpack.RawMessage
	if err := msgpack.Unmarshal(payload, &parts); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	if len(parts) < 4 {
		return nil, fmt.Errorf("payload has %d elements, want ≥4", len(parts))
	}

	// Timestamp: float64 seconds since epoch
	var ts float64
	if err := msgpack.Unmarshal(parts[0], &ts); err != nil {
		return nil, fmt.Errorf("decode timestamp: %w", err)
	}
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)
	m.Timestamp = time.Unix(sec, nsec)

	if err := msgpack.Unmarshal(parts[1], &m.Title); err != nil {
		return nil, fmt.Errorf("decode title: %w", err)
	}
	if err := msgpack.Unmarshal(parts[2], &m.Content); err != nil {
		return nil, fmt.Errorf("decode content: %w", err)
	}
	if err := msgpack.Unmarshal(parts[3], &m.Fields); err != nil {
		return nil, fmt.Errorf("decode fields: %w", err)
	}

	// Recompute message hash (same payload that was signed over)
	m.Hash = m.computeHash(payload)

	return m, nil
}

// Verify checks the Ed25519 signature against the source identity's public key.
func (m *LXMessage) Verify(pubKey ed25519.PublicKey) bool {
	payload, err := m.packPayload()
	if err != nil {
		return false
	}

	hash := m.computeHash(payload)

	signed := make([]byte, 0, HeaderSize+len(payload)+len(hash))
	signed = append(signed, m.DestinationHash...)
	signed = append(signed, m.SourceHash...)
	signed = append(signed, payload...)
	signed = append(signed, hash...)

	return ed25519.Verify(pubKey, signed, m.Signature)
}

// ID returns the message hash as a hex string, suitable for logging.
// Returns "" if the hash has not been computed yet.
func (m *LXMessage) ID() string {
	if len(m.Hash) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", m.Hash[:8]) // first 8 bytes for brevity
}

// timestampFloat64ToBytes is used internally if we ever need the raw float
// representation (e.g. for propagation packaging).
func timestampFloat64ToBytes(ts float64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, math.Float64bits(ts))
	return b
}
