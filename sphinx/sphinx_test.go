package sphinx

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nbd-wtf/go-nostr"
)

func TestNewSphinx(t *testing.T) {
	_, err := NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create new sphinx: %v", err)
	}
}

func TestEncodeDecode(t *testing.T) {
	sphinx, err := NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create new sphinx: %v", err)
	}

	message := []byte("hello world")
	pubKeys := []*secp256k1.PublicKey{sphinx.publicKey}

	onion, err := sphinx.Encode(message, pubKeys)
	if err != nil {
		t.Fatalf("Failed to encode message: %v", err)
	}

	decoded, _, err := sphinx.Decode(onion)
	if err != nil {
		t.Fatalf("Failed to decode message: %v", err)
	}

	if !bytes.Equal(message, decoded) {
		t.Fatalf("Decoded message does not match original message")
	}
}

func TestMultiHopEncryption(t *testing.T) {
	// Create multiple sphinx instances (nodes)
	node1, err := NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create node1: %v", err)
	}
	
	node2, err := NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create node2: %v", err)
	}
	
	node3, err := NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create node3: %v", err)
	}

	originalMessage := []byte("secret message for multi-hop")
	
	// Order of public keys is important: node1 -> node2 -> node3
	path := []*secp256k1.PublicKey{
		node1.publicKey,
		node2.publicKey,
		node3.publicKey,
	}

	// Create a sender (client) to encode the message
	sender, err := NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}

	// Encode the message by layering encryption for each hop
	onion, err := sender.Encode(originalMessage, path)
	if err != nil {
		t.Fatalf("Failed to encode multi-hop message: %v", err)
	}

	// Test that message cannot be read directly - it should be encrypted
	if bytes.Contains(onion, originalMessage) {
		t.Errorf("Original message should not be readable in encrypted onion")
	}

	// Now test the decryption chain:
	// Node 1 decrypts first
	layer1, nextPub1, err := node1.Decode(onion)
	if err != nil {
		t.Fatalf("Node1 failed to decrypt: %v", err)
	}

	// Node 2 decrypts second layer
	layer2, nextPub2, err := node2.Decode(layer1)
	if err != nil {
		t.Fatalf("Node2 failed to decrypt: %v", err)
	}

	// Node 3 decrypts final layer
	final, nextPub3, err := node3.Decode(layer2)
	if err != nil {
		t.Fatalf("Node3 failed to decrypt: %v", err)
	}

	// Verify the final message is correct
	if !bytes.Equal(originalMessage, final) {
		t.Errorf("Final message does not match original. Got: %q, Want: %q", string(final), string(originalMessage))
	}

	// Verify that each step properly chains to the next node
	// In a real implementation, these public keys would indicate the next destination
	if nextPub1 == nil {
		t.Error("Node1 should provide next hop information")
	}
	if nextPub2 == nil {
		t.Error("Node2 should provide next hop information")
	}
	if nextPub3 == nil {
		t.Error("Node3 should provide next hop information")
	}
}

func TestMultiHopWithWrongOrder(t *testing.T) {
	// This should fail because nodes try to decrypt in wrong order
	node1, _ := NewSphinx()
	node2, _ := NewSphinx()
	node3, _ := NewSphinx()

	originalMessage := []byte("test wrong order")
	path := []*secp256k1.PublicKey{
		node1.publicKey,
		node2.publicKey,
		node3.publicKey,
	}

	sender, _ := NewSphinx()
	onion, err := sender.Encode(originalMessage, path)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	// Try to decrypt starting from the wrong node (should fail or produce garbled data)
	_, _, err = node3.Decode(onion) // Should fail - message encrypted for node1 first
	if err == nil {
		t.Error("Node3 should not be able to decrypt message intended for node1 first")
	}
}

func TestEmptyPath(t *testing.T) {
	sphinx, _ := NewSphinx()
	message := []byte("test")
	
	// Empty path should return original message without encryption
	result, err := sphinx.Encode(message, []*secp256k1.PublicKey{})
	if err != nil {
		t.Fatalf("Failed with empty path: %v", err)
	}

	if !bytes.Equal(result, message) {
		t.Errorf("Empty path should return original message. Got: %q, Want: %q", string(result), string(message))
	}
}

func TestSingleHopIntegrity(t *testing.T) {
	node, _ := NewSphinx()
	original := []byte("single hop test")
	
	encoded, err := node.Encode(original, []*secp256k1.PublicKey{node.publicKey})
	if err != nil {
		t.Fatalf("Failed to encode single hop: %v", err)
	}
	
	decoded, _, err := node.Decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode single hop: %v", err)
	}
	
	if !bytes.Equal(original, decoded) {
		t.Errorf("Single hop failed integrity check. Got: %q, Want: %q", string(decoded), string(original))
	}
}

func TestMessageSizeVariation(t *testing.T) {
	node1, _ := NewSphinx()
	node2, _ := NewSphinx()
	
	path := []*secp256k1.PublicKey{node1.publicKey, node2.publicKey}
	sender, _ := NewSphinx()
	
	testMessages := [][]byte{
		[]byte("short"),
		[]byte("medium length message"),
		[]byte("a much longer message that should stress the encryption implementation properly"),
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255, 254, 253}, // binary data
		[]byte{}, // empty
		make([]byte, 1000), // large message
	}
	
	// Fill large message with random bytes
	rand.Read(testMessages[5])
	
	for _, msg := range testMessages {
		encoded, err := sender.Encode(msg, path)
		if err != nil {
			t.Fatalf("Failed to encode message %q: %v", string(msg), err)
		}
		
		// First hop
		firstLayer, _, _ := node1.Decode(encoded)
		
		// Second hop
		decoded, _, err := node2.Decode(firstLayer)
		if err != nil {
			t.Fatalf("Failed to decode second hop for message %q: %v", string(msg), err)
		}
		
		if !bytes.Equal(msg, decoded) {
			t.Errorf("Message size %d failed integrity check", len(msg))
		}
	}
}

func TestSharedSecretConsistency(t *testing.T) {
	nodeA, _ := NewSphinx()
	nodeB, _ := NewSphinx()
	
	// Both nodes should generate the same shared secret
	secretA, err := nodeA.GenerateSharedSecret(nodeB.publicKey)
	if err != nil {
		t.Fatalf("Failed to generate secret for nodeA: %v", err)
	}
	
	secretB, err := nodeB.GenerateSharedSecret(nodeA.publicKey)
	if err != nil {
		t.Fatalf("Failed to generate secret for nodeB: %v", err)
	}
	
	if !bytes.Equal(secretA, secretB) {
		t.Error("Shared secrets do not match - ECDH failed")
	}
}

func TestSecretVSActualEncryption(t *testing.T) {
	node1, _ := NewSphinx()
	node2, _ := NewSphinx()
	
	message := []byte("test encryption");
	path := []*secp256k1.PublicKey{node1.publicKey};
	
	encoded, _ := node2.Encode(message, path)
	decoded, _, _ := node1.Decode(encoded)
	
	if !bytes.Equal(message, decoded) {
		t.Error("Encryption/decryption failed despite matching keys")
	}
}

func BenchmarkMultiHopEncryption(b *testing.B) {
	node1, _ := NewSphinx()
	node2, _ := NewSphinx()
	node3, _ := NewSphinx()
	
	path := []*secp256k1.PublicKey{node1.publicKey, node2.publicKey, node3.publicKey}
	sender, _ := NewSphinx()
	
	message := []byte("benchmark message")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded, err := sender.Encode(message, path)
		if err != nil {
			b.Fatalf("Failed to encode: %v", err)
		}
		
		layer1, _, _ := node1.Decode(encoded)
		layer2, _, _ := node2.Decode(layer1)
		_, _, _ = node3.Decode(layer2)
	}
}

func BenchmarkGenerateSharedSecret(b *testing.B) {
	nodeA, _ := NewSphinx()
	nodeB, _ := NewSphinx()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = nodeA.GenerateSharedSecret(nodeB.publicKey)
	}
}

// Helper function to create a test Nostr event
func createTestEvent() *nostr.Event {
	sk := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(sk)
	
	event := &nostr.Event{
		PubKey:    pub,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1, // Text note
		Tags:      nostr.Tags{},
		Content:   "This is a test Nostr event for onion routing!",
	}
	
	event.Sign(sk)
	return event
}

// Helper function to compare two events for equality
func eventsEqual(a, b *nostr.Event) bool {
	return a.ID == b.ID &&
		a.PubKey == b.PubKey &&
		a.CreatedAt == b.CreatedAt &&
		a.Kind == b.Kind &&
		a.Content == b.Content &&
		a.Sig == b.Sig &&
		len(a.Tags) == len(b.Tags)
}

func TestNostrEventSingleHop(t *testing.T) {
	node, err := NewSphinx()
	if err != nil {
		t.Fatalf("Failed to create sphinx node: %v", err)
	}

	// Create a test Nostr event
	originalEvent := createTestEvent()
	
	// Serialize the event to JSON
	eventBytes, err := json.Marshal(originalEvent)
	if err != nil {
		t.Fatalf("Failed to marshal Nostr event: %v", err)
	}

	// Encrypt the event through one hop
	path := []*secp256k1.PublicKey{node.publicKey}
	sender, _ := NewSphinx()
	
	encrypted, err := sender.Encode(eventBytes, path)
	if err != nil {
		t.Fatalf("Failed to encrypt Nostr event: %v", err)
	}

	// Decrypt the event
	decrypted, _, err := node.Decode(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt Nostr event: %v", err)
	}

	// Deserialize back to event
	var recoveredEvent nostr.Event
	err = json.Unmarshal(decrypted, &recoveredEvent)
	if err != nil {
		t.Fatalf("Failed to unmarshal recovered Nostr event: %v", err)
	}

	// Verify the events are identical
	if !eventsEqual(originalEvent, &recoveredEvent) {
		t.Errorf("Recovered event does not match original")
		t.Errorf("Original: %+v", originalEvent)
		t.Errorf("Recovered: %+v", recoveredEvent)
	}
}

func TestNostrEventMultiHop(t *testing.T) {
	// Create 3 relay nodes
	relay1, _ := NewSphinx()
	relay2, _ := NewSphinx()
	relay3, _ := NewSphinx()

	// Create a test Nostr event with more complex content
	originalEvent := createTestEvent()
	originalEvent.Content = "Multi-hop onion routed Nostr message! 🧅"
	originalEvent.Tags = nostr.Tags{
		{"t", "onionrouting"},
		{"t", "nostr"},
		{"relay", "wss://relay1.example.com"},
	}
	
	// Re-sign after modifying content and tags
	sk := nostr.GeneratePrivateKey()
	originalEvent.Sign(sk)

	// Serialize the event
	eventBytes, err := json.Marshal(originalEvent)
	if err != nil {
		t.Fatalf("Failed to marshal Nostr event: %v", err)
	}

	// Define the routing path: relay1 -> relay2 -> relay3
	path := []*secp256k1.PublicKey{
		relay1.publicKey,
		relay2.publicKey,
		relay3.publicKey,
	}

	// Sender encrypts the event for the path
	sender, _ := NewSphinx()
	encrypted, err := sender.Encode(eventBytes, path)
	if err != nil {
		t.Fatalf("Failed to encrypt Nostr event: %v", err)
	}

	// Verify the original event content is not visible in encrypted form
	if bytes.Contains(encrypted, []byte(originalEvent.Content)) {
		t.Error("Original event content should not be visible in encrypted onion")
	}
	if bytes.Contains(encrypted, []byte(originalEvent.PubKey)) {
		t.Error("Original event pubkey should not be visible in encrypted onion")
	}

	// Simulate onion routing through the relay network
	// Relay 1 processes first layer
	layer1, _, err := relay1.Decode(encrypted)
	if err != nil {
		t.Fatalf("Relay1 failed to decrypt first layer: %v", err)
	}

	// Relay 2 processes second layer
	layer2, _, err := relay2.Decode(layer1)
	if err != nil {
		t.Fatalf("Relay2 failed to decrypt second layer: %v", err)
	}

	// Relay 3 (final destination) processes final layer
	finalBytes, _, err := relay3.Decode(layer2)
	if err != nil {
		t.Fatalf("Relay3 failed to decrypt final layer: %v", err)
	}

	// Deserialize the final event
	var finalEvent nostr.Event
	err = json.Unmarshal(finalBytes, &finalEvent)
	if err != nil {
		t.Fatalf("Failed to unmarshal final Nostr event: %v", err)
	}

	// Verify the event survived the multi-hop journey intact
	if !eventsEqual(originalEvent, &finalEvent) {
		t.Errorf("Final event does not match original after multi-hop routing")
		t.Errorf("Original ID: %s, Final ID: %s", originalEvent.ID, finalEvent.ID)
		t.Errorf("Original Content: %s", originalEvent.Content)
		t.Errorf("Final Content: %s", finalEvent.Content)
	}
}

func TestNostrEventVariousKinds(t *testing.T) {
	relay1, _ := NewSphinx()
	relay2, _ := NewSphinx()
	path := []*secp256k1.PublicKey{relay1.publicKey, relay2.publicKey}
	sender, _ := NewSphinx()

	// Test different kinds of Nostr events
	testCases := []struct {
		name    string
		kind    int
		content string
		tags    nostr.Tags
	}{
		{
			name:    "Text Note",
			kind:    1,
			content: "Hello Nostr World!",
			tags:    nostr.Tags{},
		},
		{
			name:    "Set Metadata", 
			kind:    0,
			content: `{"name":"Alice","about":"Onion routing enthusiast"}`,
			tags:    nostr.Tags{},
		},
		{
			name:    "Reaction",
			kind:    7,
			content: "🚀",
			tags:    nostr.Tags{{"e", "some-event-id"}, {"p", "some-pubkey"}},
		},
		{
			name:    "Direct Message",
			kind:    4,
			content: "secret message",
			tags:    nostr.Tags{{"p", "recipient-pubkey"}},
		},
		{
			name:    "Channel Message",
			kind:    42,
			content: "Message in a channel",
			tags:    nostr.Tags{{"e", "channel-id", "root"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create event of specific kind
			sk := nostr.GeneratePrivateKey()
			pub, _ := nostr.GetPublicKey(sk)
			
			event := &nostr.Event{
				PubKey:    pub,
				CreatedAt: nostr.Timestamp(time.Now().Unix()),
				Kind:      tc.kind,
				Tags:      tc.tags,
				Content:   tc.content,
			}
			event.Sign(sk)

			// Serialize and encrypt
			eventBytes, _ := json.Marshal(event)
			encrypted, err := sender.Encode(eventBytes, path)
			if err != nil {
				t.Fatalf("Failed to encrypt event kind %d: %v", tc.kind, err)
			}

			// Decrypt through relays
			layer1, _, _ := relay1.Decode(encrypted)
			final, _, err := relay2.Decode(layer1)
			if err != nil {
				t.Fatalf("Failed to decrypt event kind %d: %v", tc.kind, err)
			}

			// Verify
			var recoveredEvent nostr.Event
			json.Unmarshal(final, &recoveredEvent)
			
			if !eventsEqual(event, &recoveredEvent) {
				t.Errorf("Event kind %d failed integrity check", tc.kind)
			}
		})
	}
}

func TestNostrEventWithLargeContent(t *testing.T) {
	node, _ := NewSphinx()
	sender, _ := NewSphinx()
	
	// Create an event with large content (simulating a long article or list)
	longContent := "This is a very long Nostr event content that simulates a large article or extensive post. "
	for i := 0; i < 100; i++ {
		longContent += "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
	}
	
	event := createTestEvent()
	event.Content = longContent
	
	// Add many tags
	for i := 0; i < 50; i++ {
		event.Tags = append(event.Tags, nostr.Tag{"t", "tag" + string(rune(i))})
	}
	
	sk := nostr.GeneratePrivateKey()
	event.Sign(sk)

	eventBytes, _ := json.Marshal(event)
	
	// Test that large events can be encrypted/decrypted
	encrypted, err := sender.Encode(eventBytes, []*secp256k1.PublicKey{node.publicKey})
	if err != nil {
		t.Fatalf("Failed to encrypt large event: %v", err)
	}

	decrypted, _, err := node.Decode(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt large event: %v", err)
	}

	var recoveredEvent nostr.Event
	err = json.Unmarshal(decrypted, &recoveredEvent)
	if err != nil {
		t.Fatalf("Failed to unmarshal large event: %v", err)
	}

	if !eventsEqual(event, &recoveredEvent) {
		t.Error("Large event failed integrity check")
	}
}

func TestNostrEventInvalidation(t *testing.T) {
	node, _ := NewSphinx()
	sender, _ := NewSphinx()
	
	event := createTestEvent()
	eventBytes, _ := json.Marshal(event)
	
	encrypted, _ := sender.Encode(eventBytes, []*secp256k1.PublicKey{node.publicKey})
	
	// Corrupt some bytes in the middle of the encrypted message
	if len(encrypted) > 100 {
		encrypted[50] ^= 0xFF // Flip bits
		encrypted[75] ^= 0xFF
	}
	
	// Should fail to decrypt
	_, _, err := node.Decode(encrypted)
	if err == nil {
		t.Error("Corrupted event should fail to decrypt")
	}
}

func BenchmarkNostrEventMultiHop(b *testing.B) {
	relay1, _ := NewSphinx()
	relay2, _ := NewSphinx() 
	relay3, _ := NewSphinx()
	sender, _ := NewSphinx()
	
	path := []*secp256k1.PublicKey{relay1.publicKey, relay2.publicKey, relay3.publicKey}
	
	event := createTestEvent()
	eventBytes, _ := json.Marshal(event)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := sender.Encode(eventBytes, path)
		layer1, _, _ := relay1.Decode(encrypted)
		layer2, _, _ := relay2.Decode(layer1)
		_, _, _ = relay3.Decode(layer2)
	}
}

// TestNostrEventRealisticScenario tests a realistic Nostr onion routing scenario
func TestNostrEventRealisticScenario(t *testing.T) {
	// Simulate a realistic network topology with 5 relays
	relays := make([]*Sphinx, 5)
	for i := 0; i < 5; i++ {
		relay, err := NewSphinx()
		if err != nil {
			t.Fatalf("Failed to create relay %d: %v", i, err)
		}
		relays[i] = relay
	}
	
	// Client wants to send a private message through the onion network
	client, _ := NewSphinx()
	
	// Create a realistic Nostr event (encrypted DM)
	sk := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(sk)
	recipientSk := nostr.GeneratePrivateKey()
	recipientPub, _ := nostr.GetPublicKey(recipientSk)
	
	// Create an encrypted DM (NIP-04 style)
	plainDM := "This is a secret message being sent through onion routing!"
	
	event := &nostr.Event{
		PubKey:    pub,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      4, // Encrypted Direct Message
		Tags: nostr.Tags{
			{"p", recipientPub},
		},
		Content: plainDM, // In reality this would be NIP-04 encrypted, but for testing we use plain text
	}
	event.Sign(sk)
	
	// Define a 3-hop path through the relay network
	path := []*secp256k1.PublicKey{
		relays[0].publicKey, // Entry relay
		relays[2].publicKey, // Middle relay  
		relays[4].publicKey, // Exit relay
	}
	
	// Serialize and encrypt the event
	eventBytes, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal event: %v", err)
	}
	
	// Client creates the onion
	onion, err := client.Encode(eventBytes, path)
	if err != nil {
		t.Fatalf("Failed to create onion: %v", err)
	}
	
	// Verify privacy: original content should not be visible
	if bytes.Contains(onion, []byte(plainDM)) {
		t.Error("Original message content should not be visible in onion")
	}
	if bytes.Contains(onion, []byte(event.PubKey)) {
		t.Error("Original sender pubkey should not be visible in onion")
	}
	if bytes.Contains(onion, []byte(recipientPub)) {
		t.Error("Recipient pubkey should not be visible in onion")
	}
	
	// Simulate network routing
	t.Logf("Original onion size: %d bytes", len(onion))
	
	// Entry relay (relays[0]) processes first layer
	layer1, senderPub1, err := relays[0].Decode(onion)
	if err != nil {
		t.Fatalf("Entry relay failed to decrypt: %v", err)
	}
	t.Logf("After entry relay: %d bytes, sender: %s", len(layer1), senderPub1.SerializeCompressed())
	
	// Middle relay (relays[2]) processes second layer
	layer2, senderPub2, err := relays[2].Decode(layer1)
	if err != nil {
		t.Fatalf("Middle relay failed to decrypt: %v", err)
	}
	t.Logf("After middle relay: %d bytes, sender: %s", len(layer2), senderPub2.SerializeCompressed())
	
	// Exit relay (relays[4]) processes final layer
	finalPayload, senderPub3, err := relays[4].Decode(layer2)
	if err != nil {
		t.Fatalf("Exit relay failed to decrypt: %v", err)
	}
	t.Logf("After exit relay: %d bytes, sender: %s", len(finalPayload), senderPub3.SerializeCompressed())
	
	// Exit relay reconstructs the original Nostr event
	var finalEvent nostr.Event
	err = json.Unmarshal(finalPayload, &finalEvent)
	if err != nil {
		t.Fatalf("Failed to unmarshal final event: %v", err)
	}
	
	// Verify the event survived the journey
	if !eventsEqual(event, &finalEvent) {
		t.Error("Event was corrupted during onion routing")
		t.Errorf("Original: ID=%s, Content=%s", event.ID, event.Content)
		t.Errorf("Final: ID=%s, Content=%s", finalEvent.ID, finalEvent.Content)
	}
	
	// Verify event properties
	if finalEvent.Kind != 4 {
		t.Errorf("Expected kind 4 (DM), got %d", finalEvent.Kind)
	}
	
	if len(finalEvent.Tags) == 0 || finalEvent.Tags[0][1] != recipientPub {
		t.Error("Recipient tag was lost or corrupted")
	}
	
	// Verify signature is still valid
	if ok, err := finalEvent.CheckSignature(); !ok || err != nil {
		t.Errorf("Event signature validation failed: ok=%v, err=%v", ok, err)
	}
	
	t.Logf("Successfully routed Nostr DM through 3-hop onion path!")
	t.Logf("Event ID: %s", finalEvent.ID)
	t.Logf("From: %s", finalEvent.PubKey)
	t.Logf("To: %s", recipientPub)
	t.Logf("Message: %s", finalEvent.Content)
}
