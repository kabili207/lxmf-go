package core

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"math"
	"runtime"
	"sync"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	// StampSize is the size of a stamp in bytes (SHA-256 digest).
	StampSize = 32

	// WorkblockExpandRounds is the number of HKDF expansion rounds for
	// regular delivery stamps.
	WorkblockExpandRounds = 3000

	// WorkblockExpandRoundsPN is the expansion round count for propagation
	// node stamps.
	WorkblockExpandRoundsPN = 1000

	// WorkblockExpandRoundsPeering is the expansion round count for peering
	// key generation.
	WorkblockExpandRoundsPeering = 25

	// CostTicket is the synthetic stamp value returned when a stamp is
	// validated via a ticket rather than PoW.
	CostTicket = 0x100

	// TruncatedHashSize is the size of a truncated SHA-256 hash (16 bytes).
	TruncatedHashSize = 16
)

// hkdf performs HKDF extract-then-expand with HMAC-SHA256, matching the
// Reticulum implementation in RNS/Cryptography/HKDF.py.
func hkdf(length int, deriveFrom, salt, ctx []byte) []byte {
	hashLen := 32

	if len(salt) == 0 {
		salt = make([]byte, hashLen)
	}
	if ctx == nil {
		ctx = []byte{}
	}

	// Extract: PRK = HMAC-SHA256(salt, deriveFrom)
	mac := hmac.New(sha256.New, salt)
	mac.Write(deriveFrom)
	prk := mac.Sum(nil)

	// Expand
	block := []byte{}
	derived := make([]byte, 0, length)
	rounds := int(math.Ceil(float64(length) / float64(hashLen)))

	for i := 0; i < rounds; i++ {
		mac = hmac.New(sha256.New, prk)
		mac.Write(block)
		mac.Write(ctx)
		mac.Write([]byte{byte((i + 1) % 256)})
		block = mac.Sum(nil)
		derived = append(derived, block...)
	}

	return derived[:length]
}

// fullHash computes SHA-256, matching RNS.Identity.full_hash.
func fullHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// truncatedHash computes a truncated SHA-256 (first 16 bytes), matching
// RNS.Identity.truncated_hash.
func truncatedHash(data []byte) []byte {
	return fullHash(data)[:TruncatedHashSize]
}

// StampWorkblock generates the HKDF-expanded workblock for stamp mining and
// validation. The material is typically the message_id (message hash).
func StampWorkblock(material []byte, expandRounds int) []byte {
	workblock := make([]byte, 0, expandRounds*256)
	for n := 0; n < expandRounds; n++ {
		nPacked, _ := msgpack.Marshal(n)
		saltInput := make([]byte, 0, len(material)+len(nPacked))
		saltInput = append(saltInput, material...)
		saltInput = append(saltInput, nPacked...)
		salt := fullHash(saltInput)

		block := hkdf(256, material, salt, nil)
		workblock = append(workblock, block...)
	}
	return workblock
}

// StampValid checks whether a stamp meets the target cost (number of leading
// zero bits) against the given workblock.
func StampValid(stamp []byte, targetCost int, workblock []byte) bool {
	if targetCost < 1 || targetCost > 255 {
		return false
	}

	// target = 1 << (256 - targetCost)
	target := new(big.Int).Lsh(big.NewInt(1), uint(256-targetCost))

	combined := make([]byte, 0, len(workblock)+len(stamp))
	combined = append(combined, workblock...)
	combined = append(combined, stamp...)
	result := fullHash(combined)

	val := new(big.Int).SetBytes(result)
	return val.Cmp(target) <= 0
}

// StampValue returns the number of leading zero bits in
// SHA-256(workblock + stamp). This is the "value" or difficulty of the stamp.
func StampValue(workblock, stamp []byte) int {
	combined := make([]byte, 0, len(workblock)+len(stamp))
	combined = append(combined, workblock...)
	combined = append(combined, stamp...)
	material := fullHash(combined)

	value := 0
	i := new(big.Int).SetBytes(material)
	bit256 := new(big.Int).Lsh(big.NewInt(1), 255)

	for value < 256 {
		if i.Bit(255-value) != 0 {
			break
		}
		value++
	}
	_ = bit256

	return value
}

// GenerateStamp mines a stamp that satisfies the given cost for the provided
// message ID. It uses multiple goroutines to parallelize the search. The
// returned stamp is 32 bytes. The second return value is the stamp's bit value.
//
// Pass a cancellable context to abort generation early (e.g. on shutdown).
func GenerateStamp(ctx context.Context, messageID []byte, stampCost int, expandRounds int) ([]byte, int, error) {
	workblock := StampWorkblock(messageID, expandRounds)

	workers := runtime.NumCPU()
	if workers > 12 {
		workers = workers / 2
	}
	if workers < 1 {
		workers = 1
	}

	type result struct {
		stamp []byte
	}

	resultCh := make(chan result, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stamp := make([]byte, StampSize)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if _, err := rand.Read(stamp); err != nil {
					return
				}
				if StampValid(stamp, stampCost, workblock) {
					// Copy to avoid race on the backing array.
					found := make([]byte, StampSize)
					copy(found, stamp)
					select {
					case resultCh <- result{stamp: found}:
						cancel()
					default:
					}
					return
				}
			}
		}()
	}

	// Wait for either a result or cancellation.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	res, ok := <-resultCh
	if !ok || res.stamp == nil {
		return nil, 0, ctx.Err()
	}

	value := StampValue(workblock, res.stamp)
	return res.stamp, value, nil
}

// ValidateStamp checks whether an LXMessage's stamp is valid, either by
// matching an inbound ticket or by verifying the PoW against the target cost.
// Returns true and the stamp value if valid.
func ValidateStamp(msg *LXMessage, targetCost int, tickets [][]byte) (bool, int) {
	// Check tickets first (cheap comparison).
	if len(tickets) > 0 && len(msg.Hash) > 0 {
		for _, ticket := range tickets {
			expected := truncatedHash(append(ticket, msg.Hash...))
			if len(msg.Stamp) == len(expected) && hmac.Equal(msg.Stamp, expected) {
				return true, CostTicket
			}
		}
	}

	if len(msg.Stamp) == 0 {
		return false, 0
	}

	workblock := StampWorkblock(msg.Hash, WorkblockExpandRounds)
	if StampValid(msg.Stamp, targetCost, workblock) {
		return true, StampValue(workblock, msg.Stamp)
	}
	return false, 0
}
