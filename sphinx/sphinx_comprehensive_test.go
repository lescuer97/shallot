package sphinx

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nbd-wtf/go-nostr"
)

// TestCompleteEncryptionDecryptionCycle tests the full cycle with various configurations
func TestCompleteEncryptionDecryptionCycle(t *testing.T) {
	testCases := []struct {
		name     string
		hops     int
		msgSize  int
		validate func(*testing.T, []byte, []byte)
	}{
		{
			name:    "1-hop small message",
			hops:    1,
			msgSize: 10,
			validate: func(t *testing.T, orig, decoded []byte) {
				if !bytes.Equal(orig, decoded) {
					t.Errorf("Messages don't match")
				}
			},
		},
		{
			name:    "3-hop medium message",
			hops:    3,
			msgSize: 500,
			validate: func(t *testing.T, orig, decoded []byte) {
				if !bytes.Equal(orig, decoded) {
					t.Errorf("Messages don't match")
				}
			},
		},
		{
			name:    "5-hop large message",
			hops:    5,
			msgSize: 5000,
			validate: func(t *testing.T, orig, decoded []byte) {
				if !bytes.Equal(orig, decoded) {
					t.Errorf("Messages don't match")
				}
			},
		},
		{
			name:    "10-hop max stress",
			hops:    10,
			msgSize: 1000,
			validate: func(t *testing.T, orig, decoded []byte) {
				if !bytes.Equal(orig, decoded) {
					t.Errorf("Messages don't match")
				}
			},
		},
		{
			name:    "2-hop empty message",
			hops:    2,
			msgSize: 0,
			validate: func(t *testing.T, orig, decoded []byte) {
				if len(decoded) != 0 {
					t.Errorf("Expected empty message, got %d bytes", len(decoded))
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create nodes for the path
			nodes := make([]*Sphinx, tc.hops)
			path := make([]*secp256k1.PublicKey, tc.hops)
			
			for i := 0; i < tc.hops; i++ {
				node, err := NewSphinx()
				if err != nil {
					t.Fatalf("Failed to create node %d: %v", i, err)
				}
				nodes[i] = node
				path[i] = node.publicKey
			}

			// Create sender
			sender, err := NewSphinx()
			if err != nil {
				t.Fatalf("Failed to create sender: %v", err)
			}

			// Generate test message
			var originalMessage []byte
			if tc.msgSize > 0 {
				originalMessage = make([]byte, tc.msgSize)
				rand.Read(originalMessage)
			}

			// Encode message
			startEncode := time.Now()
			encrypted, err := sender.Encode(originalMessage, path)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}
			encodeTime := time.Since(startEncode)

			// Log encryption efficiency
			overhead := float64(len(encrypted)-tc.msgSize) / float64(tc.msgSize+1) * 100
			t.Logf("Encryption: %d bytes -> %d bytes (%.1f%% overhead) in %v", 
				tc.msgSize, len(encrypted), overhead, encodeTime)

			// Decode through all hops
			startDecode := time.Now()
			current := encrypted
			for i, node := range nodes {
				layer, _, err := node.Decode(current)
				if err != nil {
					t.Fatalf("Failed to decode at hop %d: %v", i+1, err)
				}
				current = layer
			}
			decodeTime := time.Since(startDecode)

			t.Logf("Decryption: %d hops in %v", tc.hops, decodeTime)

			// Validate result
			tc.validate(t, originalMessage, current)
		})
	}
}

// TestEncryptionDecryptionWithNostrEvents tests complete cycle with various Nostr event types
func TestEncryptionDecryptionWithNostrEvents(t *testing.T) {
	testEvents := []struct {
		name        string
		createEvent func() *nostr.Event
		hops        int
	}{
		{
			name: "Text Note - Single Hop",
			createEvent: func() *nostr.Event {
				return createComplexEvent(1, "Hello Nostr! This is a test message.", nil)
			},
			hops: 1,
		},
		{
			name: "Metadata Event - Multi Hop",
			createEvent: func() *nostr.Event {
				content := `{"name":"Alice","about":"Privacy advocate","picture":"https://example.com/avatar.jpg","website":"https://alice.com"}`
				return createComplexEvent(0, content, nil)
			},
			hops: 3,
		},
		{
			name: "Direct Message - Secure Routing",
			createEvent: func() *nostr.Event {
				recipientPub := "2d38a56c4303f1ddb655b5d2b4b160a35b8a8b0b6f5e9d7a8b3c4e8f9a1b2c3d"
				tags := nostr.Tags{{"p", recipientPub}}
				return createComplexEvent(4, "Secret message through onion routing!", tags)
			},
			hops: 5,
		},
		{
			name: "Reaction Event - Fast Routing",
			createEvent: func() *nostr.Event {
				eventId := "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
				authorPub := "3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f"
				tags := nostr.Tags{{"e", eventId}, {"p", authorPub}}
				return createComplexEvent(7, "🔥", tags)
			},
			hops: 2,
		},
		{
			name: "Long Form Content - Stress Test",
			createEvent: func() *nostr.Event {
				longContent := "# This is a Long Form Article\n\n"
				longContent += strings.Repeat("This is paragraph content that should test the encryption with larger payloads. ", 100)
				longContent += "\n\n## Conclusion\nEnd of article."
				
				tags := nostr.Tags{
					{"title", "Test Article"},
					{"summary", "Testing onion routing with long content"},
					{"t", "test"}, {"t", "onionrouting"}, {"t", "nostr"},
				}
				return createComplexEvent(30023, longContent, tags)
			},
			hops: 4,
		},
	}

	for _, te := range testEvents {
		t.Run(te.name, func(t *testing.T) {
			// Create relay network
			relays := make([]*Sphinx, te.hops)
			path := make([]*secp256k1.PublicKey, te.hops)
			
			for i := 0; i < te.hops; i++ {
				relay, err := NewSphinx()
				if err != nil {
					t.Fatalf("Failed to create relay %d: %v", i, err)
				}
				relays[i] = relay
				path[i] = relay.publicKey
			}

			// Create client
			client, err := NewSphinx()
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			// Create and serialize event
			originalEvent := te.createEvent()
			eventBytes, err := json.Marshal(originalEvent)
			if err != nil {
				t.Fatalf("Failed to marshal event: %v", err)
			}

			t.Logf("Original event size: %d bytes, kind: %d", len(eventBytes), originalEvent.Kind)

			// Encrypt through onion layers
			encrypted, err := client.Encode(eventBytes, path)
			if err != nil {
				t.Fatalf("Failed to encrypt event: %v", err)
			}

			// Verify privacy - sensitive data should not be visible
			if bytes.Contains(encrypted, []byte(originalEvent.Content)) && len(originalEvent.Content) > 10 {
				t.Error("Event content should not be visible in encrypted form")
			}
			if bytes.Contains(encrypted, []byte(originalEvent.PubKey)) {
				t.Error("Event pubkey should not be visible in encrypted form")
			}

			// Route through network
			current := encrypted
			totalSize := len(encrypted)
			for i, relay := range relays {
				layer, sender, err := relay.Decode(current)
				if err != nil {
					t.Fatalf("Relay %d failed to decrypt: %v", i+1, err)
				}
				current = layer
				t.Logf("Hop %d: %d bytes -> %d bytes (sender: %x)", 
					i+1, totalSize, len(layer), sender.SerializeCompressed()[:8])
				totalSize = len(layer)
			}

			// Reconstruct event
			var finalEvent nostr.Event
			err = json.Unmarshal(current, &finalEvent)
			if err != nil {
				t.Fatalf("Failed to unmarshal final event: %v", err)
			}

			// Verify integrity
			if !eventsEqual(originalEvent, &finalEvent) {
				t.Error("Event integrity lost during routing")
				t.Logf("Original ID: %s", originalEvent.ID)
				t.Logf("Final ID: %s", finalEvent.ID)
			}

			// Verify signature
			if ok, err := finalEvent.CheckSignature(); !ok || err != nil {
				t.Errorf("Signature validation failed: ok=%v, err=%v", ok, err)
			}

			t.Logf("Success: Event %s routed through %d hops", finalEvent.ID, te.hops)
		})
	}
}

// TestErrorConditions tests various error scenarios
func TestErrorConditions(t *testing.T) {
	node1, _ := NewSphinx()
	node2, _ := NewSphinx()
	sender, _ := NewSphinx()

	t.Run("Corrupted Encryption", func(t *testing.T) {
		message := []byte("test message")
		path := []*secp256k1.PublicKey{node1.publicKey}
		encrypted, _ := sender.Encode(message, path)
		
		// Corrupt the encrypted data
		if len(encrypted) > 50 {
			encrypted[40] ^= 0xFF
			encrypted[45] ^= 0xFF
			encrypted[50] ^= 0xFF
		}
		
		_, _, err := node1.Decode(encrypted)
		if err == nil {
			t.Error("Expected error when decrypting corrupted data")
		}
	})

	t.Run("Wrong Decryption Order", func(t *testing.T) {
		message := []byte("ordered message")
		path := []*secp256k1.PublicKey{node1.publicKey, node2.publicKey}
		encrypted, _ := sender.Encode(message, path)
		
		// Try to decrypt with node2 first (should fail)
		_, _, err := node2.Decode(encrypted)
		if err == nil {
			t.Error("Expected error when decrypting in wrong order")
		}
	})

	t.Run("Truncated Message", func(t *testing.T) {
		message := []byte("truncation test")
		path := []*secp256k1.PublicKey{node1.publicKey}
		encrypted, _ := sender.Encode(message, path)
		
		// Truncate the message
		if len(encrypted) > 10 {
			truncated := encrypted[:len(encrypted)/2]
			_, _, err := node1.Decode(truncated)
			if err == nil {
				t.Error("Expected error when decrypting truncated data")
			}
		}
	})

	t.Run("Invalid Public Key in Message", func(t *testing.T) {
		// Create a message with invalid public key bytes
		invalidMsg := make([]byte, 100)
		rand.Read(invalidMsg)
		
		_, _, err := node1.Decode(invalidMsg)
		if err == nil {
			t.Error("Expected error when decrypting message with invalid pubkey")
		}
	})

	t.Run("Empty Message Edge Cases", func(t *testing.T) {
		// Test extremely small messages
		testSizes := []int{0, 1, 2, 32, 33}
		
		for _, size := range testSizes {
			message := make([]byte, size)
			if size > 0 {
				rand.Read(message)
			}
			
			encrypted, err := sender.Encode(message, []*secp256k1.PublicKey{node1.publicKey})
			if err != nil {
				t.Errorf("Failed to encrypt %d-byte message: %v", size, err)
				continue
			}
			
			decrypted, _, err := node1.Decode(encrypted)
			if err != nil {
				t.Errorf("Failed to decrypt %d-byte message: %v", size, err)
				continue
			}
			
			if !bytes.Equal(message, decrypted) {
				t.Errorf("Message integrity failed for %d bytes", size)
			}
		}
	})
}

// TestConcurrentEncryptionDecryption tests thread safety
func TestConcurrentEncryptionDecryption(t *testing.T) {
	const numGoroutines = 50
	const numOperations = 10
	
	// Create network nodes
	relays := make([]*Sphinx, 3)
	path := make([]*secp256k1.PublicKey, 3)
	for i := 0; i < 3; i++ {
		relay, _ := NewSphinx()
		relays[i] = relay
		path[i] = relay.publicKey
	}

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOperations)
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			sender, err := NewSphinx()
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: failed to create sender: %v", goroutineID, err)
				return
			}
			
			for j := 0; j < numOperations; j++ {
				// Create unique message for this operation
				message := []byte(fmt.Sprintf("concurrent-test-g%d-op%d", goroutineID, j))
				
				// Encrypt
				encrypted, err := sender.Encode(message, path)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d op %d: encode failed: %v", goroutineID, j, err)
					continue
				}
				
				// Decrypt through all hops
				current := encrypted
				for hopNum, relay := range relays {
					layer, _, err := relay.Decode(current)
					if err != nil {
						errors <- fmt.Errorf("goroutine %d op %d hop %d: decode failed: %v", 
							goroutineID, j, hopNum, err)
						break
					}
					current = layer
				}
				
				// Verify
				if !bytes.Equal(message, current) {
					errors <- fmt.Errorf("goroutine %d op %d: message integrity failed", goroutineID, j)
				}
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	errorCount := 0
	for err := range errors {
		t.Error(err)
		errorCount++
	}
	
	if errorCount > 0 {
		t.Errorf("Had %d errors in concurrent test", errorCount)
	} else {
		t.Logf("Successfully completed %d concurrent operations across %d goroutines", 
			numGoroutines*numOperations, numGoroutines)
	}
}

// TestLargeNetworkSimulation simulates a large network with many hops
func TestLargeNetworkSimulation(t *testing.T) {
	const networkSize = 20
	const maxHops = 8
	
	// Create a large network of nodes  
	network := make([]*Sphinx, networkSize)
	for i := 0; i < networkSize; i++ {
		node, err := NewSphinx()
		if err != nil {
			t.Fatalf("Failed to create network node %d: %v", i, err)
		}
		network[i] = node
	}
	
	client, _ := NewSphinx()
	
	// Test different path lengths through the network
	for hops := 1; hops <= maxHops; hops++ {
		t.Run(fmt.Sprintf("NetworkPath_%d_hops", hops), func(t *testing.T) {
			// Select random nodes for path
			path := make([]*secp256k1.PublicKey, hops)
			selectedNodes := make([]*Sphinx, hops)
			
			for i := 0; i < hops; i++ {
				nodeIdx := (i * 7) % networkSize // Deterministic but spread out selection
				selectedNodes[i] = network[nodeIdx]
				path[i] = network[nodeIdx].publicKey
			}
			
			// Create test event
			event := createComplexEvent(1, fmt.Sprintf("Network test message through %d hops", hops), nil)
			eventBytes, _ := json.Marshal(event)
			
			// Route through network
			start := time.Now()
			encrypted, err := client.Encode(eventBytes, path)
			if err != nil {
				t.Fatalf("Failed to encode for %d hops: %v", hops, err)
			}
			
			// Decrypt through selected path
			current := encrypted
			for i, node := range selectedNodes {
				layer, _, err := node.Decode(current)
				if err != nil {
					t.Fatalf("Node %d failed to decrypt: %v", i, err)
				}
				current = layer
			}
			routingTime := time.Since(start)
			
			// Verify final event
			var finalEvent nostr.Event
			json.Unmarshal(current, &finalEvent)
			
			if !eventsEqual(event, &finalEvent) {
				t.Errorf("Event corrupted during %d-hop routing", hops)
			}
			
			overhead := float64(len(encrypted) - len(eventBytes)) / float64(len(eventBytes)) * 100
			t.Logf("Hops: %d, Time: %v, Overhead: %.1f%%", hops, routingTime, overhead)
		})
	}
}

// TestEncryptionPerformanceAnalysis analyzes performance characteristics
func TestEncryptionPerformanceAnalysis(t *testing.T) {
	messageSizes := []int{100, 1000, 5000, 10000, 50000}
	hopCounts := []int{1, 3, 5, 8}
	
	for _, msgSize := range messageSizes {
		for _, hops := range hopCounts {
			testName := fmt.Sprintf("Size_%d_Hops_%d", msgSize, hops)
			t.Run(testName, func(t *testing.T) {
				// Setup
				nodes := make([]*Sphinx, hops)
				path := make([]*secp256k1.PublicKey, hops)
				for i := 0; i < hops; i++ {
					node, _ := NewSphinx()
					nodes[i] = node
					path[i] = node.publicKey
				}
				
				sender, _ := NewSphinx()
				message := make([]byte, msgSize)
				rand.Read(message)
				
				// Measure encryption
				encStart := time.Now()
				encrypted, err := sender.Encode(message, path)
				encTime := time.Since(encStart)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
				
				// Measure decryption
				decStart := time.Now()
				current := encrypted
				for _, node := range nodes {
					layer, _, err := node.Decode(current)
					if err != nil {
						t.Fatalf("Decryption failed: %v", err)
					}
					current = layer
				}
				decTime := time.Since(decStart)
				
				// Calculate metrics
				overhead := float64(len(encrypted) - msgSize) / float64(msgSize) * 100
				encThroughput := float64(msgSize) / encTime.Seconds() / 1024 / 1024 // MB/s
				decThroughput := float64(msgSize) / decTime.Seconds() / 1024 / 1024 // MB/s
				
				t.Logf("Size: %6d, Hops: %d, Enc: %8v (%.2f MB/s), Dec: %8v (%.2f MB/s), Overhead: %5.1f%%",
					msgSize, hops, encTime, encThroughput, decTime, decThroughput, overhead)
				
				// Verify integrity
				if !bytes.Equal(message, current) {
					t.Error("Message integrity lost")
				}
			})
		}
	}
}

// Helper function to create complex Nostr events for testing
func createComplexEvent(kind int, content string, tags nostr.Tags) *nostr.Event {
	sk := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(sk)
	
	if tags == nil {
		tags = nostr.Tags{}
	}
	
	event := &nostr.Event{
		PubKey:    pub,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      kind,
		Tags:      tags,
		Content:   content,
	}
	
	event.Sign(sk)
	return event
}

// TestMaximumCapacity tests the limits of the encryption system
func TestMaximumCapacity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping capacity test in short mode")
	}
	
	t.Run("Maximum_Message_Size", func(t *testing.T) {
		node, _ := NewSphinx()
		sender, _ := NewSphinx()
		path := []*secp256k1.PublicKey{node.publicKey}
		
		// Test increasingly large messages
		sizes := []int{100000, 500000, 1000000} // 100KB, 500KB, 1MB
		
		for _, size := range sizes {
			t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
				message := make([]byte, size)
				rand.Read(message)
				
				start := time.Now()
				encrypted, err := sender.Encode(message, path)
				if err != nil {
					t.Fatalf("Failed to encrypt %d byte message: %v", size, err)
				}
				
				decrypted, _, err := node.Decode(encrypted)
				if err != nil {
					t.Fatalf("Failed to decrypt %d byte message: %v", size, err)
				}
				duration := time.Since(start)
				
				if !bytes.Equal(message, decrypted) {
					t.Error("Large message integrity failed")
				}
				
				throughput := float64(size) / duration.Seconds() / 1024 / 1024
				t.Logf("Size: %d bytes, Time: %v, Throughput: %.2f MB/s", size, duration, throughput)
			})
		}
	})
	
	t.Run("Maximum_Hop_Count", func(t *testing.T) {
		maxHops := 15
		message := []byte("max hop test")
		
		// Create nodes for maximum hops
		nodes := make([]*Sphinx, maxHops)
		path := make([]*secp256k1.PublicKey, maxHops)
		for i := 0; i < maxHops; i++ {
			node, _ := NewSphinx()
			nodes[i] = node
			path[i] = node.publicKey
		}
		
		sender, _ := NewSphinx()
		
		start := time.Now()
		encrypted, err := sender.Encode(message, path)
		if err != nil {
			t.Fatalf("Failed to encrypt with %d hops: %v", maxHops, err)
		}
		
		// Decrypt through all hops
		current := encrypted
		for i, node := range nodes {
			layer, _, err := node.Decode(current)
			if err != nil {
				t.Fatalf("Failed to decrypt at hop %d: %v", i+1, err)
			}
			current = layer
		}
		duration := time.Since(start)
		
		if !bytes.Equal(message, current) {
			t.Error("Message integrity failed with maximum hops")
		}
		
		overhead := float64(len(encrypted) - len(message)) / float64(len(message)) * 100
		t.Logf("Max hops: %d, Time: %v, Overhead: %.1f%%", maxHops, duration, overhead)
	})
}
