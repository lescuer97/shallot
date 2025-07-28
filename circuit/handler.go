package circuit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lescuer97/shallot/sphinx"
	"github.com/nbd-wtf/go-nostr"
)

// Session represents a single onion routing session
type Session struct {
	ID                   string // Unique session identifier
	OriginalSenderPubKey []byte // Original sender's public key
	PreviousRelayURL     string // URL of the previous relay in the circuit
	PreviousRelayPubKey  []byte // Public key of the previous relay
	NextRelayURL         string // URL of the next relay (can be empty for final destination)
	CreatedAt            time.Time
}

// CircuitHandler manages onion routing circuits for Nostr events
type CircuitHandler struct {
	sphinx      sphinx.Sphinx
	connections map[string]*nostr.Relay
	sessions    map[string]*Session // Map of session ID to Session
	mu          sync.RWMutex
}

// NewCircuitHandler creates a new circuit handler
func NewCircuitHandler(s sphinx.Sphinx) *CircuitHandler {
	handler := &CircuitHandler{
		sphinx:      s,
		connections: make(map[string]*nostr.Relay),
		sessions:    make(map[string]*Session),
	}

	// Start a background goroutine to clean up stale connections
	go handler.cleanupStaleConnections()

	return handler
}

// HandleOnionEvent processes a Nostr event that contains onion routing data
func (ch *CircuitHandler) HandleOnionEvent(ctx context.Context, event *nostr.Event) error {
	if event.Kind != 720 {
		return fmt.Errorf("event is not an onion routing message (kind 720)")
	}

	// Decode the onion packet from the event content (hex encoded)
	onionPacketBytes, err := hex.DecodeString(event.Content)
	if err != nil {
		return fmt.Errorf("failed to decode onion packet: %w", err)
	}

	var packet sphinx.OnionPacket
	if err := json.Unmarshal(onionPacketBytes, &packet); err != nil {
		return fmt.Errorf("failed to unmarshal onion packet: %w", err)
	}

	// Validate packet size - all onion packets should be exactly MaxPacketSize
	if len(packet.EncryptedPayload) != sphinx.MaxPacketSize {
		log.Printf("ERROR: Invalid onion packet size. Expected %d bytes, got %d bytes",
			sphinx.MaxPacketSize, len(packet.EncryptedPayload))
		log.Printf("Packet content (first 100 chars): %s...", string(packet.EncryptedPayload[:min(100, len(packet.EncryptedPayload))]))
		return fmt.Errorf("invalid onion packet size: expected %d bytes, got %d bytes",
			sphinx.MaxPacketSize, len(packet.EncryptedPayload))
	}

	// Create or retrieve session for this onion packet
	sessionID := hex.EncodeToString(packet.Header.SenderPubKey)
	ch.mu.Lock()
	session, exists := ch.sessions[sessionID]
	if !exists {
		// Create new session
		session = &Session{
			ID:                   sessionID,
			OriginalSenderPubKey: packet.Header.SenderPubKey,
			PreviousRelayURL:     "", // Will be populated by previous relay
			PreviousRelayPubKey:  nil, // Will be populated by previous relay
			NextRelayURL:         "", // Will be populated after decryption
			CreatedAt:            time.Now(),
		}
		ch.sessions[sessionID] = session
	}
	ch.mu.Unlock()

	// Decrypt the onion layer
	nextHopURL, payload, err := ch.sphinx.Decode(&packet)
	if err != nil {
		return fmt.Errorf("failed to decode onion packet: %w", err)
	}

	// Update session with next hop information
	ch.mu.Lock()
	session.NextRelayURL = nextHopURL
	ch.mu.Unlock()

	log.Printf("Decoded onion packet. Next hop: %s, Is final: %t", nextHopURL, nextHopURL == "")

	// If there's a next hop, forward the message
	if nextHopURL != "" {
		log.Println("forwarding to next Hop")
		return ch.forwardToNextHop(ctx, nextHopURL, payload, session.OriginalSenderPubKey)
	}

	// If this is the final destination, process the inner payload
	return ch.processFinalPayload(ctx, payload)
}

// forwardToNextHop sends the decrypted payload to the next relay in the circuit
func (ch *CircuitHandler) forwardToNextHop(ctx context.Context, nextHopURL string, payload []byte, originalSenderKey []byte) error {
	// Get or create a connection to the next relay (ensuring only one connection per relay)
	relay, err := ch.getConnection(ctx, nextHopURL)
	if err != nil {
		return fmt.Errorf("failed to get connection to %s: %w", nextHopURL, err)
	}

	// Add padding to ensure all packets are the same size for anonymity
	paddedPayload, err := sphinx.AddPadding(payload, sphinx.MaxPacketSize)
	if err != nil {
		return fmt.Errorf("failed to add padding to payload: %w", err)
	}

	// Create a new onion packet for the next hop with proper header
	nextPacket := sphinx.OnionPacket{
		Header: sphinx.OnionHeader{
			SenderPubKey:    originalSenderKey,
			NextRelayURL:    sphinx.Relay{}, // Will be set when the next relay processes it
			EncryptedLength: len(payload),   // Set the length of the actual content (before padding)
		},
		EncryptedPayload: paddedPayload, // Send the padded payload
	}

	// Marshal the packet
	packetBytes, err := json.Marshal(nextPacket)
	if err != nil {
		return fmt.Errorf("failed to marshal onion packet: %w", err)
	}

	// Convert to hex string for Nostr event content
	content := hex.EncodeToString(packetBytes)

	// Create a Nostr event for the next hop
	nextEvent := nostr.Event{
		PubKey:    hex.EncodeToString(ch.sphinx.GetPublicKey().SerializeCompressed()),
		CreatedAt: nostr.Now(),
		Kind:      720, // Onion routing message
		Tags:      []nostr.Tag{},
		Content:   content,
	}

	// Sign the event
	err = nextEvent.Sign(hex.EncodeToString(ch.sphinx.PrivateKey.Serialize()))
	if err != nil {
		return fmt.Errorf("Failed to sign onion event: %w", err)
	}

	log.Printf("\n nextEvent %+v", nextEvent)
	// Publish the event to the next relay
	err = relay.Publish(ctx, nextEvent)
	if err != nil {
		// If publishing fails, the connection might be stale
		// Close the connection and try to reconnect
		ch.closeConnection(nextHopURL)

		// Try to get a new connection
		relay, err = ch.getConnection(ctx, nextHopURL)
		if err != nil {
			return fmt.Errorf("failed to reconnect to %s: %w", nextHopURL, err)
		}

		// Try publishing again
		err = relay.Publish(ctx, nextEvent)
		if err != nil {
			return fmt.Errorf("failed to publish to %s after reconnect: %w", nextHopURL, err)
		}
	}

	log.Printf("Forwarded onion packet to next hop: %s", nextHopURL)
	return nil
}

// processFinalPayload handles the final payload when this relay is the destination
func (ch *CircuitHandler) processFinalPayload(ctx context.Context, payload []byte) error {
	// Print the final payload/event as requested
	log.Printf("Reached final destination. Decrypted payload: %s", string(payload))

	// In a real implementation, this might involve:
	// 1. Parsing the payload as a Nostr event
	// 2. Storing it in the relay's event store
	// 3. Broadcasting it to connected clients
	// For now, we just log it as requested

	return nil
}

// getConnection gets or creates a WebSocket connection to a relay (ensuring only one per relay)
func (ch *CircuitHandler) getConnection(ctx context.Context, relayURL string) (*nostr.Relay, error) {
	// Check if we already have a connection to this relay
	ch.mu.RLock()
	relay, exists := ch.connections[relayURL]
	ch.mu.RUnlock()

	if exists && relay != nil {
		// Check if the connection is still alive by checking ConnectionError
		// Note: This is a simplified check. In practice, you might want more robust health checking.
		return relay, nil
	}

	// Create a new connection with timeout
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	newRelay, err := nostr.RelayConnect(connectCtx, relayURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay %s: %w", relayURL, err)
	}

	// Store the connection
	ch.mu.Lock()
	ch.connections[relayURL] = newRelay
	ch.mu.Unlock()

	log.Printf("Created new connection to relay: %s", relayURL)
	return newRelay, nil
}

// closeConnection closes and removes a connection to a relay
func (ch *CircuitHandler) closeConnection(relayURL string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if relay, exists := ch.connections[relayURL]; exists {
		if relay != nil {
			relay.Close()
		}
		delete(ch.connections, relayURL)
	}
}

// cleanupStaleConnections periodically checks for and removes stale connections
func (ch *CircuitHandler) cleanupStaleConnections() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ch.mu.Lock()
		for relayURL, relay := range ch.connections {
			if relay != nil {
				// In a real implementation, you'd check if the connection is still healthy
				// For now, we'll just keep the connections open
				_ = relayURL
			}
		}
		ch.mu.Unlock()
	}
}

// Close closes all connections
func (ch *CircuitHandler) Close() {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	for relayURL, relay := range ch.connections {
		if relay != nil {
			relay.Close()
		}
		delete(ch.connections, relayURL)
	}
}

// Helper function for min (since we're using an older Go version)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
