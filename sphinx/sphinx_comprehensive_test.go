package sphinx

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
)

// TestFullCycleWithNostrEvents tests the full encryption and decryption cycle with Nostr events.
func TestFullCycleWithNostrEvents(t *testing.T) {
	testCases := []struct {
		name        string
		hops        int
		createEvent func() *nostr.Event
	}{
		{
			name: "Simple Text Note - 2 Hops",
			hops: 2,
			createEvent: func() *nostr.Event {
				return &nostr.Event{
					Content: "Hello, this is a test.",
					Kind:    1,
				}
			},
		},
		{
			name: "Metadata Event - 3 Hops",
			hops: 3,
			createEvent: func() *nostr.Event {
				return &nostr.Event{
					Content: `{"name": "test-user", "about": "testing sphinx"}`,
					Kind:    0,
				}
			},
		},
		{
			name: "DM Event - 4 Hops",
			hops: 4,
			createEvent: func() *nostr.Event {
				return &nostr.Event{
					Content: "A secret direct message.",
					Kind:    4,
					Tags:    nostr.Tags{{"p", "some-pubkey"}},
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sender, err := NewSphinx()
			assert.NoError(t, err, "Failed to create sender")

			// Create relays
			relays := make([]*Relay, tc.hops)
			relayInstances := make([]*Sphinx, tc.hops)
			for i := 0; i < tc.hops; i++ {
				r, _ := NewSphinx()
				relayInstances[i] = r
				relays[i], _ = NewRelay(r.GetPublicKey(), fmt.Sprintf("wss://relay%d.com", i))
			}

			// Create and serialize event
			event := tc.createEvent()
			eventBytes, err := json.Marshal(event)
			assert.NoError(t, err, "Failed to marshal event")

			// Encode the event
			packet, err := sender.Encode(eventBytes, relays)
			assert.NoError(t, err, "Failed to encode event")

			// Simulate routing through the relays
			var nextPayload []byte = packet.EncryptedPayload
			for i := 0; i < tc.hops; i++ {
				_, decryptedPayload, decErr := relayInstances[i].Decode(&OnionPacket{
					SenderPubKey:     packet.SenderPubKey,
					EncryptedPayload: nextPayload,
				})
				assert.NoError(t, decErr, "Failed to decode at hop %d", i)
				nextPayload = decryptedPayload
			}

			// The final payload should be the original event
			var finalEvent nostr.Event
			err = json.Unmarshal(nextPayload, &finalEvent)
			assert.NoError(t, err, "Failed to unmarshal final event")

			// Verify the content
			assert.Equal(t, event.Content, finalEvent.Content, "Event content should match")
			assert.Equal(t, event.Kind, finalEvent.Kind, "Event kind should match")
		})
	}
}

// TestErrorHandling tests various error conditions.
func TestErrorHandling(t *testing.T) {
	sender, _ := NewSphinx()
	relay, _ := NewSphinx()
	r, _ := NewRelay(relay.GetPublicKey(), "wss://relay.com")

	t.Run("Too Many Hops", func(t *testing.T) {
		relays := make([]*Relay, NumMaxHops+1)
		for i := range relays {
			relays[i] = r
		}
		_, err := sender.Encode([]byte("test"), relays)
		assert.Error(t, err, "Expected error for too many hops")
	})

	t.Run("No Relays", func(t *testing.T) {
		_, err := sender.Encode([]byte("test"), []*Relay{})
		assert.Error(t, err, "Expected error for no relays")
	})

	t.Run("Corrupted Payload", func(t *testing.T) {
		packet, _ := sender.Encode([]byte("a message"), []*Relay{r})

		// Corrupt the payload
		if len(packet.EncryptedPayload) > 10 {
			packet.EncryptedPayload[5] ^= 0xff
		}

		_, _, err := relay.Decode(packet)
		assert.Error(t, err, "Expected error for corrupted payload")
	})
}

// TestPerformance benchmarks the encoding and decoding process.
func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	sender, _ := NewSphinx()
	hops := 5
	relays := make([]*Relay, hops)
	relayInstances := make([]*Sphinx, hops)
	for i := 0; i < hops; i++ {
		r, _ := NewSphinx()
		relayInstances[i] = r
		relays[i], _ = NewRelay(r.GetPublicKey(), fmt.Sprintf("wss://relay%d.com", i))
	}

	message := make([]byte, 2048) // 2KB message
	rand.Read(message)

	// Benchmark encoding
	t.Run("Encoding", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			_, err := sender.Encode(message, relays)
			if err != nil {
				t.Fatalf("Encoding failed: %v", err)
			}
		}
	})

	// Prepare a packet for decoding benchmark
	packet, _ := sender.Encode(message, relays)

	// Benchmark decoding
	t.Run("Decoding", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			var currentPayload = packet.EncryptedPayload
			for hop := 0; hop < hops; hop++ {
				_, p, err := relayInstances[hop].Decode(&OnionPacket{
					SenderPubKey:     packet.SenderPubKey,
					EncryptedPayload: currentPayload,
				})
				if err != nil {
					t.Fatalf("Decoding failed at hop %d: %v", hop, err)
				}
				currentPayload = p
			}
		}
	})
}
