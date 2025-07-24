package circuit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

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
	
	if handler.connections == nil {
		t.Fatal("Connections map not initialized")
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
	
	// This test mainly ensures the function doesn't panic
	// The actual printing is a side effect we can't easily test
	payload := []byte("test final payload")
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
