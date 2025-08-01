package utils

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nbd-wtf/go-nostr"
)

func TestProcessNIP66EventRealNostrKey(t *testing.T) {
	// Test with a real Nostr public key (32-byte X-only)
	// This is a valid Nostr public key from actual Nostr usage
	realNostrPubKey := "5a462d7447302581353731326d42794f53506c4546746d5445644c4d63784c4a"

	event := &nostr.Event{
		PubKey:    realNostrPubKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      30166,
		Tags: nostr.Tags{
			[]string{"d", "wss://test.relay.com"},
			[]string{"k", "720"},
			[]string{"N", "66"},
		},
		Content: "{}",
	}

	// Process the event
	relayInfo, err := processNIP66Event(event)
	if err != nil {
		t.Fatalf("processNIP66Event failed: %v", err)
	}

	// Verify the results
	if relayInfo.PublicKey == nil {
		t.Error("Expected public key to not be nil")
	}

	// Check that it's 32 bytes
	if len(relayInfo.PublicKey) != 32 {
		t.Errorf("Expected public key to be 32 bytes, got %d", len(relayInfo.PublicKey))
	}

	// Check that it matches the original
	expectedBytes, _ := hex.DecodeString(realNostrPubKey)
	for i, b := range expectedBytes {
		if relayInfo.PublicKey[i] != b {
			t.Errorf("Byte mismatch at position %d: expected %x, got %x", i, b, relayInfo.PublicKey[i])
		}
	}

	// Verify it's a valid secp256k1 point by converting to full public key
	// Prepend 0x02 byte to make it a compressed public key format
	fullPubKeyBytes := append([]byte{0x02}, relayInfo.PublicKey...)
	_, err = secp256k1.ParsePubKey(fullPubKeyBytes)
	if err != nil {
		t.Errorf("Failed to parse as valid secp256k1 public key: %v", err)
	}
}

func TestProcessNIP66Event(t *testing.T) {
	// Create a mock NIP-66 event with a valid 32-byte X-only public key
	validXOnlyPubKey := "5a462d7447302581353731326d42794f53506c4546746d5445644c4d63784c4a"

	event := &nostr.Event{
		PubKey:    validXOnlyPubKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      30166,
		Tags: nostr.Tags{
			[]string{"d", "wss://test.relay.com"},
			[]string{"k", "720"},
			[]string{"N", "66"},
		},
		Content: "{}",
	}

	// Process the event
	relayInfo, err := processNIP66Event(event)
	if err != nil {
		t.Fatalf("processNIP66Event failed: %v", err)
	}

	// Verify the results
	if relayInfo.PublicKey == nil {
		t.Error("Expected public key to not be nil")
	}

	// Check that it's 32 bytes
	if len(relayInfo.PublicKey) != 32 {
		t.Errorf("Expected public key to be 32 bytes, got %d", len(relayInfo.PublicKey))
	}

	// Check that it matches the original
	expectedBytes, _ := hex.DecodeString(validXOnlyPubKey)
	for i, b := range expectedBytes {
		if relayInfo.PublicKey[i] != b {
			t.Errorf("Byte mismatch at position %d: expected %x, got %x", i, b, relayInfo.PublicKey[i])
		}
	}

	if relayInfo.RelayURL != "wss://test.relay.com" {
		t.Errorf("Expected relay URL 'wss://test.relay.com', got '%s'", relayInfo.RelayURL)
	}

	if !relayInfo.SupportsOnionKind {
		t.Error("Expected SupportsOnionKind to be true")
	}
}

func TestProcessNIP66EventWithoutOnionSupport(t *testing.T) {
	// Create a mock NIP-66 event without onion support
	validXOnlyPubKey := "5a462d7447302581353731326d42794f53506c4546746d5445644c4d63784c4a"

	event := &nostr.Event{
		PubKey:    validXOnlyPubKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      30166,
		Tags: nostr.Tags{
			[]string{"d", "wss://test.relay.com"},
			[]string{"k", "1"},
			[]string{"N", "66"},
		},
		Content: "{}",
	}

	// Process the event
	relayInfo, err := processNIP66Event(event)
	if err != nil {
		t.Fatalf("processNIP66Event failed: %v", err)
	}

	// Verify the results
	if relayInfo.RelayURL != "wss://test.relay.com" {
		t.Errorf("Expected relay URL 'wss://test.relay.com', got '%s'", relayInfo.RelayURL)
	}

	if relayInfo.SupportsOnionKind {
		t.Error("Expected SupportsOnionKind to be false")
	}
}

func TestProcessNIP66EventInvalidPubKey(t *testing.T) {
	// Test with invalid public key length
	event := &nostr.Event{
		PubKey:    "abcdef123456", // Too short
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      30166,
		Tags: nostr.Tags{
			[]string{"d", "wss://test.relay.com"},
			[]string{"k", "720"},
			[]string{"N", "66"},
		},
		Content: "{}",
	}

	_, err := processNIP66Event(event)
	if err == nil {
		t.Error("Expected error for invalid public key length")
	}
}

func TestProcessNIP66EventInvalidCurvePoint(t *testing.T) {
	// Test with 32 bytes that don't represent a valid curve point
	// This is 32 bytes of 0xFF which is not a valid X coordinate
	invalidPubKey := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	event := &nostr.Event{
		PubKey:    invalidPubKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      30166,
		Tags: nostr.Tags{
			[]string{"d", "wss://test.relay.com"},
			[]string{"k", "720"},
			[]string{"N", "66"},
		},
		Content: "{}",
	}

	_, err := processNIP66Event(event)
	if err == nil {
		t.Error("Expected error for invalid curve point")
	}
}

func TestGetOnionCapableRelays(t *testing.T) {
	// Create mock public keys (32-byte arrays)
	pubKey1 := make([]byte, 32)
	pubKey1[0] = 0x01
	pubKey2 := make([]byte, 32)
	pubKey2[0] = 0x02
	pubKey3 := make([]byte, 32)
	pubKey3[0] = 0x03

	// Create a map with mixed relay types
	relays := map[string]RelayInfo{
		"relay1": {
			PublicKey:         pubKey1,
			RelayURL:          "wss://relay1.com",
			SupportsOnionKind: true,
			LastAnnounced:     time.Now(),
		},
		"relay2": {
			PublicKey:         pubKey2,
			RelayURL:          "wss://relay2.com",
			SupportsOnionKind: false,
			LastAnnounced:     time.Now(),
		},
		"relay3": {
			PublicKey:         pubKey3,
			RelayURL:          "wss://relay3.com",
			SupportsOnionKind: true,
			LastAnnounced:     time.Now(),
		},
	}

	// Filter for onion-capable relays
	onionRelays := GetOnionCapableRelays(relays)

	// Verify the results
	if len(onionRelays) != 2 {
		t.Errorf("Expected 2 onion-capable relays, got %d", len(onionRelays))
	}

	if _, exists := onionRelays["relay1"]; !exists {
		t.Error("Expected relay1 to be in onion-capable relays")
	}

	if _, exists := onionRelays["relay3"]; !exists {
		t.Error("Expected relay3 to be in onion-capable relays")
	}

	if _, exists := onionRelays["relay2"]; exists {
		t.Error("Expected relay2 to not be in onion-capable relays")
	}
}
