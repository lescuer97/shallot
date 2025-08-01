package circuit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/lescuer97/shallot/sphinx"
	"github.com/nbd-wtf/go-nostr"
)

// TestCircuitHandlerCreation tests that we can create a circuit handler
func TestCircuitHandlerCreation(t *testing.T) {
	sphinx, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create sphinx: %v", err)
	}

	handler := NewCircuitHandler(sphinx)
	if handler == nil {
		t.Fatal("Failed to create circuit handler")
	}

	if handler.sessions == nil {
		t.Fatal("Sessions map not initialized")
	}
}

// TestHandleOnionEventWrongKind tests that non-720 events are rejected
func TestHandleOnionEventWrongKind(t *testing.T) {
	sphinx, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create sphinx: %v", err)
	}

	handler := NewCircuitHandler(sphinx)

	event := &nostr.Event{
		Kind: 1, // Not 720
	}

	err = handler.HandleOnionEvent(context.Background(), event)
	if err == nil {
		t.Fatal("Expected error for non-720 event, got nil")
	}

	if err.Error() != "event is not an onion routing message (kind 720)" {
		t.Errorf("Unexpected error message: %v", err.Error())
	}
}

// TestHandleOnionEventInvalidContent tests handling of invalid content
func TestHandleOnionEventInvalidContent(t *testing.T) {
	sphinx, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create sphinx: %v", err)
	}

	handler := NewCircuitHandler(sphinx)

	event := &nostr.Event{
		Kind:    720,
		Content: "invalid hex content",
	}

	err = handler.HandleOnionEvent(context.Background(), event)
	if err == nil {
		t.Fatal("Expected error for invalid content, got nil")
	}

	if err.Error() != "failed to decode onion packet: encoding/hex: invalid byte: U+0069 'i'" {
		t.Errorf("Unexpected error message: %v", err.Error())
	}
}

// TestHandleOnionEventInvalidSize tests handling of invalid packet sizes
func TestHandleOnionEventInvalidSize(t *testing.T) {
	s, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create sphinx: %v", err)
	}

	handler := NewCircuitHandler(s)

	// Create a packet with invalid size
	packet := sphinx.OnionPacket{
		EncryptedPayload: []byte("invalid size packet"), // Not MaxPacketSize
	}

	packetBytes, err := json.Marshal(packet)
	if err != nil {
		t.Fatalf("Failed to marshal packet: %v", err)
	}

	event := &nostr.Event{
		Kind:    720,
		Content: hex.EncodeToString(packetBytes),
	}

	err = handler.HandleOnionEvent(context.Background(), event)
	if err == nil {
		t.Fatal("Expected error for invalid packet size, got nil")
	}

	// The error message should indicate the incorrect size
	expectedErrMsg := "invalid onion packet size: expected 12288 bytes, got 19 bytes"
	if err.Error() != expectedErrMsg {
		t.Errorf("Unexpected error message. Expected: %s, Got: %s", expectedErrMsg, err.Error())
	}
}

// TestProcessFinalPayload tests the final payload handling
func TestProcessFinalPayload(t *testing.T) {
	s, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create sphinx: %v", err)
	}

	handler := NewCircuitHandler(s)

	// Create a proper LastHopPayload for testing
	lastHopPayload := sphinx.LastHopPayload{
		MessageType: sphinx.Proxy,
		TargetUrl:   "test_destination",
		Payload:     []byte("test final payload"),
	}

	// Marshal the LastHopPayload as CBOR (as it would be in the actual implementation)
	payload, err := cbor.Marshal(lastHopPayload)
	if err != nil {
		t.Fatalf("Failed to marshal LastHopPayload: %v", err)
	}

	// This test mainly ensures the function doesn't panic
	// The actual printing is a side effect we can't easily test
	err = handler.processFinalPayload(context.Background(), payload)
	if err != nil {
		t.Errorf("Unexpected error in processFinalPayload: %v", err)
	}
}

// TestEncodeDecodeOnionPacket tests the utility functions
func TestEncodeDecodeOnionPacket(t *testing.T) {
	packet := sphinx.OnionPacket{
		EncryptedPayload: []byte("test payload"),
	}

	// Test encoding
	content, err := EncodeOnionPacketToEventContent(packet)
	if err != nil {
		t.Fatalf("Failed to encode packet: %v", err)
	}

	if content == "" {
		t.Error("Encoded content is empty")
	}

	// Test decoding
	var decodedPacket sphinx.OnionPacket
	err = DecodeOnionPacketFromEventContent(content, &decodedPacket)
	if err != nil {
		t.Fatalf("Failed to decode packet: %v", err)
	}

	if string(packet.EncryptedPayload) != string(decodedPacket.EncryptedPayload) {
		t.Errorf("Payloads don't match. Expected: %s, Got: %s",
			string(packet.EncryptedPayload),
			string(decodedPacket.EncryptedPayload))
	}
}

// TestSphinxEncodeFunction tests the new 4-argument Encode function
func TestSphinxEncodeFunction(t *testing.T) {
	s, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create sphinx: %v", err)
	}

	// Create test relays
	relay1, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create relay1: %v", err)
	}
	relay1Info, err := sphinx.NewRelay(relay1.GetPublicKey(), "wss://relay1.example.com")
	if err != nil {
		t.Fatalf("Failed to create relay1 info: %v", err)
	}

	relay2, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create relay2: %v", err)
	}
	relay2Info, err := sphinx.NewRelay(relay2.GetPublicKey(), "wss://relay2.example.com")
	if err != nil {
		t.Fatalf("Failed to create relay2 info: %v", err)
	}

	relays := []*sphinx.Relay{relay1Info, relay2Info}
	message := []byte("Hello, onion routing world!")

	// Test the new 4-argument Encode function
	packet, err := s.Encode(message, relays, sphinx.Proxy, "test_destination")
	if err != nil {
		t.Fatalf("Failed to encode message: %v", err)
	}

	if packet == nil {
		t.Fatal("Encoded packet is nil")
	}

	// Check that the packet has the correct size
	if len(packet.EncryptedPayload) != sphinx.MaxPacketSize {
		t.Errorf("Packet size is incorrect. Expected: %d, Got: %d",
			sphinx.MaxPacketSize, len(packet.EncryptedPayload))
	}
}
