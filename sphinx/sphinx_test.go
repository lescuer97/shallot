package sphinx

import (
	"encoding/binary"
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

	// Create a chain of 2 relays for easier debugging
	numHops := 2
	relays := make([]*Relay, numHops)
	relayNodes := make([]*Sphinx, numHops)

	for i := 0; i < numHops; i++ {
		node, _ := NewSphinx()
		relayNodes[i] = node
		relays[i], _ = NewRelay(node.GetPublicKey(), fmt.Sprintf("wss://relay%d.com", i))
	}

	originalMessage := []byte("test message")

	packet, err := sender.Encode(originalMessage, relays)
	assert.NoError(t, err, "Encoding for multi-hop failed")

	currentPayload := packet.EncryptedPayload

	// Simulate routing through each relay
	for i := 0; i < numHops; i++ {
		_, payload, decErr := relayNodes[i].Decode(&OnionPacket{
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
	// Test addPadding and removePadding functions
	original := []byte("hello world test message")
	
	// Test padding to 100 bytes
	padded, err := addPadding(original, 100)
	assert.NoError(t, err, "Padding should not fail")
	assert.Equal(t, 100, len(padded), "Padded data should be target size")
	
	// Verify the original content is preserved
	assert.Equal(t, original, padded[:len(original)], "Original data should be preserved")
	
	// Verify padding marker
	assert.Equal(t, byte(0x80), padded[len(original)], "Padding marker should be 0x80")
	
	// Test creating a payloadWithSize format like in encoding
	payloadWithSize := make([]byte, 4+len(original))
	binary.BigEndian.PutUint32(payloadWithSize[:4], uint32(len(original)))
	copy(payloadWithSize[4:], original)
	
	// Test removePadding
	recovered, err := removePadding(payloadWithSize)
	assert.NoError(t, err, "Remove padding should not fail")
	assert.Equal(t, original, recovered, "Recovered data should match original")
}

// TestMultiHopPaddingCorrectness tests multi-hop onion with various payload sizes
// to ensure padding doesn't interfere with routing
func TestMultiHopPaddingCorrectness(t *testing.T) {
	testCases := []struct {
		name    string
		hops    int
		payload string
	}{
		{"3-hop small", 3, "small message"},
		{"4-hop medium", 4, "this is a somewhat longer message for testing multi-hop with different payload sizes"},
		{"5-hop large", 5, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sender, err := NewSphinx()
			assert.NoError(t, err, "Failed to create sender")

			// Create relay chain
			relays := make([]*Relay, tc.hops)
			relayNodes := make([]*Sphinx, tc.hops)

			for i := 0; i < tc.hops; i++ {
				node, err := NewSphinx()
				assert.NoError(t, err, "Failed to create relay node %d", i)
				relayNodes[i] = node
				relays[i], err = NewRelay(node.GetPublicKey(), fmt.Sprintf("wss://relay%d.com", i))
				assert.NoError(t, err, "Failed to create relay %d", i)
			}

			originalMessage := []byte(tc.payload)

			// Encode the message
			packet, err := sender.Encode(originalMessage, relays)
			assert.NoError(t, err, "Encoding for %s failed", tc.name)
			assert.Equal(t, MaxPacketSize, len(packet.EncryptedPayload), "Final packet should be max size")

			// Simulate routing through each relay
			currentPayload := packet.EncryptedPayload
			for i := 0; i < tc.hops; i++ {
				nextHop, payload, decErr := relayNodes[i].Decode(&OnionPacket{
					EncryptedPayload: currentPayload,
				})
				assert.NoError(t, decErr, "Decoding at hop %d failed for %s", i+1, tc.name)

				if i == tc.hops-1 {
					// Final hop should have empty nextHop and original payload
					assert.Empty(t, nextHop, "Final hop should have empty nextHop")
					assert.Equal(t, originalMessage, payload, "Final payload should match original")
				} else {
					// Intermediate hop should have nextHop URL
					assert.Equal(t, fmt.Sprintf("wss://relay%d.com", i+1), nextHop, "NextHop URL should match")
					assert.NotEmpty(t, payload, "Payload should not be empty for intermediate hop")
					currentPayload = payload
				}
			}
		})
	}
}

// TestConstantPacketSizeInMultiHop ensures that all intermediate hops always receive
// packets of exactly MaxPacketSize (12KB) to prevent traffic analysis
func TestConstantPacketSizeInMultiHop(t *testing.T) {
	testCases := []struct {
		name        string
		hops        int
		message     string
	}{
		{"2-hop tiny", 2, "tiny"},
		{"3-hop small", 3, "small message for testing constant packet size"},
		{"4-hop medium", 4, "This is a medium-sized message that should still result in constant 12KB packets at all hops regardless of the actual payload size, which is important for traffic analysis resistance in onion routing networks."},
		{"5-hop large", 5, "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur. Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur. At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga."},
		{"10-hop maximum", NumMaxHops, "Testing maximum number of hops with constant packet size - this is critical for anonymity"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sender, err := NewSphinx()
			assert.NoError(t, err, "Failed to create sender")

			// Create relay chain
			relays := make([]*Relay, tc.hops)
			relayNodes := make([]*Sphinx, tc.hops)

			for i := 0; i < tc.hops; i++ {
				node, err := NewSphinx()
				assert.NoError(t, err, "Failed to create relay node %d", i)
				relayNodes[i] = node
				relays[i], err = NewRelay(node.GetPublicKey(), fmt.Sprintf("wss://relay%d.example.com", i))
				assert.NoError(t, err, "Failed to create relay %d", i)
			}

			originalMessage := []byte(tc.message)

			// Encode the message
			packet, err := sender.Encode(originalMessage, relays)
			assert.NoError(t, err, "Encoding for %s failed", tc.name)
			
			// CRITICAL: The initial packet must be exactly MaxPacketSize
			assert.Equal(t, MaxPacketSize, len(packet.EncryptedPayload), 
				"Initial packet size must be exactly %d bytes for traffic analysis resistance", MaxPacketSize)

			// Track packet sizes at each hop to verify constant size property
			packetSizes := make([]int, tc.hops)
			currentPayload := packet.EncryptedPayload

			// Simulate routing through each relay
			for hopIndex := 0; hopIndex < tc.hops; hopIndex++ {
				// Record the input packet size for this hop
				packetSizes[hopIndex] = len(currentPayload)
				
				// CRITICAL: Every hop should receive exactly MaxPacketSize for traffic analysis resistance
				assert.Equal(t, MaxPacketSize, packetSizes[hopIndex],
					"Hop %d should receive exactly %d bytes (got %d) for traffic analysis resistance",
					hopIndex, MaxPacketSize, packetSizes[hopIndex])

				nextHop, payload, decErr := relayNodes[hopIndex].Decode(&OnionPacket{
					EncryptedPayload: currentPayload,
				})
				assert.NoError(t, decErr, "Decoding at hop %d failed for %s", hopIndex+1, tc.name)

				if hopIndex == tc.hops-1 {
					// Final hop: should have empty nextHop and original payload
					assert.Empty(t, nextHop, "Final hop should have empty nextHop")
					assert.Equal(t, originalMessage, payload, "Final payload should match original")
				} else {
					// Intermediate hop: should have nextHop URL and forwarded payload
					expectedURL := fmt.Sprintf("wss://relay%d.example.com", hopIndex+1)
					assert.Equal(t, expectedURL, nextHop, "NextHop URL should match")
					assert.NotEmpty(t, payload, "Payload should not be empty for intermediate hop")
					// CRITICAL: The forwarded payload should also be exactly MaxPacketSize
					assert.Equal(t, MaxPacketSize, len(payload), 
						"Forwarded payload from hop %d should be exactly %d bytes for traffic analysis resistance", 
						hopIndex, MaxPacketSize)
					currentPayload = payload
				}
			}

			// Verify that ALL hops received exactly 12KB
			for i, size := range packetSizes {
				assert.Equal(t, MaxPacketSize, size,
					"Hop %d must receive exactly %d bytes for anonymity (received %d)",
					i, MaxPacketSize, size)
			}

			// Log packet sizes for analysis (in verbose mode)
			t.Logf("Packet sizes for %s:", tc.name)
			for i, size := range packetSizes {
				if i == 0 {
					t.Logf("  Hop %d: %d bytes (SHOULD BE %d)", i, size, MaxPacketSize)
				} else {
					t.Logf("  Hop %d: %d bytes (intermediate)", i, size)
				}
			}
		})
	}
}

// TestTrafficAnalysisResistance specifically tests that packet sizes don't leak
// information about payload sizes through correlation attacks
func TestTrafficAnalysisResistance(t *testing.T) {
	const numHops = 3
	
	// Test different payload sizes to ensure they all result in the same initial packet size
	payloadSizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"tiny", 1},
		{"small", 16},
		{"medium", 256},
		{"large", 1024},
		{"xlarge", 4096},
	}

	sender, err := NewSphinx()
	assert.NoError(t, err, "Failed to create sender")

	// Create a consistent relay chain for all tests
	relays := make([]*Relay, numHops)
	for i := 0; i < numHops; i++ {
		node, err := NewSphinx()
		assert.NoError(t, err, "Failed to create relay node %d", i)
		relays[i], err = NewRelay(node.GetPublicKey(), fmt.Sprintf("wss://relay%d.example.com", i))
		assert.NoError(t, err, "Failed to create relay %d", i)
	}

	initialPacketSizes := make([]int, len(payloadSizes))

	// Test each payload size
	for i, test := range payloadSizes {
		var payload []byte
		if test.size > 0 {
			payload = make([]byte, test.size)
			// Fill with deterministic data
			for j := range payload {
				payload[j] = byte(j % 256)
			}
		} // else empty payload for size 0 test

		if test.size == 0 && test.name == "empty" {
			// Skip empty payload test as it's not allowed
			t.Logf("Skipping empty payload test (not supported)")
			continue
		}

		packet, err := sender.Encode(payload, relays)
		if test.size == 0 {
			assert.Error(t, err, "Empty payload should cause encoding error")
			continue
		} else {
			assert.NoError(t, err, "Encoding failed for %s payload", test.name)
		}

		initialPacketSizes[i] = len(packet.EncryptedPayload)
		
		t.Logf("Payload size %d (%s) -> Initial packet size %d", test.size, test.name, initialPacketSizes[i])
	}

	// Verify all non-zero payload sizes result in exactly the same initial packet size
	expectedSize := MaxPacketSize
	for i, test := range payloadSizes {
		if test.size == 0 {
			continue // Skip empty payload
		}
		assert.Equal(t, expectedSize, initialPacketSizes[i],
			"All payloads should result in packets of size %d (payload %s: %d bytes -> packet %d bytes)",
			expectedSize, test.name, test.size, initialPacketSizes[i])
	}

	// Ensure all sizes are identical for traffic analysis resistance
	var firstValidSize int = -1
	for i, test := range payloadSizes {
		if test.size == 0 {
			continue
		}
		if firstValidSize == -1 {
			firstValidSize = initialPacketSizes[i]
		} else {
			assert.Equal(t, firstValidSize, initialPacketSizes[i],
				"Packet size correlation detected! Payload %s creates different packet size", test.name)
		}
	}
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

	t.Run("Encode with zero-length message", func(t *testing.T) {
		s, _ := NewSphinx()
		relay, _ := NewSphinx()
		r, _ := NewRelay(relay.GetPublicKey(), "wss://relay.example.com")
		_, err := s.Encode([]byte{}, []*Relay{r})
		assert.Error(t, err, "Should not be able to encode zero-length message")
	})
}
