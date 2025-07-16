package sphinx

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
