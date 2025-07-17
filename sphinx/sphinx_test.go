package sphinx

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEncodeDecodeSingleHop tests a single-hop onion encryption and decryption.
func TestEncodeDecodeSingleHop(t *testing.T) {
	sender, err := NewSphinx()
	assert.NoError(t, err, "Failed to create sender")

	relayNode, err := NewSphinx()
	assert.NoError(t, err, "Failed to create relay node")

	relay, err := NewRelay(relayNode.GetPublicKey(), "wss://relay.example.com")
	assert.NoError(t, err, "Failed to create relay")

	message := []byte("hello world")

	packet, err := sender.Encode(message, []*Relay{relay})
	assert.NoError(t, err, "Encoding failed")

	// Relay decodes the packet
	nextHop, payload, err := relayNode.Decode(packet)
	assert.NoError(t, err, "Relay decoding failed")

	// Since it's the final hop, the nextHop should be empty
	assert.Empty(t, nextHop, "Next hop should be empty for the final relay")

	// The payload should be the original message
	assert.Equal(t, message, payload, "Decrypted payload should match original message")
}

// TestEncodeDecodeMultiHop tests a multi-hop onion encryption and decryption.
func TestEncodeDecodeMultiHop(t *testing.T) {
	sender, err := NewSphinx()
	assert.NoError(t, err, "Failed to create sender")

	// Create a chain of 3 relays
	numHops := 3
	relays := make([]*Relay, numHops)
	relayNodes := make([]*Sphinx, numHops)

	for i := 0; i < numHops; i++ {
		node, _ := NewSphinx()
		relayNodes[i] = node
		relays[i], _ = NewRelay(node.GetPublicKey(), fmt.Sprintf("wss://relay%d.com", i))
	}

	originalMessage := []byte("a secret message passed through multiple hops")

	packet, err := sender.Encode(originalMessage, relays)
	assert.NoError(t, err, "Encoding for multi-hop failed")

	currentPayload := packet.EncryptedPayload

	// Simulate routing through each relay
	for i := 0; i < numHops; i++ {
		_, payload, decErr := relayNodes[i].Decode(&OnionPacket{
			SenderPubKey:     packet.SenderPubKey,
			EncryptedPayload: currentPayload,
		})
		assert.NoError(t, decErr, "Decoding at hop %d failed", i+1)
		currentPayload = payload
	}

	// After the last hop, the payload should be the original message
	assert.Equal(t, originalMessage, currentPayload, "Final payload should match original message")
}

// TestPaddingLogic ensures padding is correctly applied.
func TestPaddingLogic(t *testing.T) {
	// This is a placeholder for where padding logic tests would go.
	// Since the simplified version does not explicitly have padding, this is a no-op for now.
	t.Skip("Padding logic test not implemented in simplified version")
}

// TestInvalidInputs checks for correct error handling with invalid inputs.
func TestInvalidInputs(t *testing.T) {
	t.Run("Invalid relay URL", func(t *testing.T) {
		dummyKey, _ := NewSphinx()
		_, err := NewRelay(dummyKey.GetPublicKey(), "invalid-url")
		assert.Error(t, err, "Expected error for invalid relay URL")
	})

	t.Run("Encode with no relays", func(t *testing.T) {
		s, _ := NewSphinx()
		_, err := s.Encode([]byte("message"), []*Relay{})
		assert.Error(t, err, "Should not be able to encode with an empty relay path")
	})
}
