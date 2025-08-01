package circuit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lescuer97/shallot/sphinx"
	"github.com/nbd-wtf/go-nostr"
)

// SessionRelay holds information about a relay used in a session
type SessionRelay struct {
	URL       string // Relay URL
	PublicKey []byte // Relay's public key
}

// Session represents a single onion routing session
type Session struct {
	ID                   string           // Unique session identifier
	OriginalSenderPubKey *btcec.PublicKey // Original sender's public key
	PreviousRelayPubKey  *btcec.PublicKey // Public key of the previous relay
	NextRelayURL         string           // URL of the next relay (can be empty for final destination)
	PreviousRelay        *nostr.Relay     // Connection to the previous relay
	NextRelay            *nostr.Relay     // Connection to the next relay
	CreatedAt            time.Time
}

// CircuitHandler manages onion routing circuits for Nostr events
type CircuitHandler struct {
	sphinx   sphinx.Sphinx
	sessions map[string]*Session // Map of session ID to Session
	mu       sync.RWMutex
}

// NewCircuitHandler creates a new circuit handler
func NewCircuitHandler(s sphinx.Sphinx) *CircuitHandler {
	handler := &CircuitHandler{
		sphinx:   s,
		sessions: make(map[string]*Session),
	}

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
		prevRelayPubkey, err := hex.DecodeString(event.PubKey)
		if err != nil {
			return err
		}

		previousRelayPubkey, err := btcec.ParsePubKey(prevRelayPubkey)
		if err != nil {
			return err
		}

		senderPubkey, err := btcec.ParsePubKey(packet.Header.SenderPubKey)
		if err != nil {
			return err
		}

		// Create new session
		session = &Session{
			ID:                   sessionID,
			OriginalSenderPubKey: senderPubkey,
			PreviousRelayPubKey:  previousRelayPubkey,
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
		return ch.forwardToNextHop(ctx, nextHopURL, payload, session.OriginalSenderPubKey, session.ID)
	}

	// If this is the final destination, process the inner payload
	return ch.processFinalPayload(ctx, payload)
}

// processFinalPayload handles the final payload at the destination
func (ch *CircuitHandler) processFinalPayload(ctx context.Context, payload []byte) error {
	// For now, just log the payload - in a real implementation, this would
	// process the final message content
	log.Printf("Processing final payload: %s", string(payload))
	return nil
}

// forwardToNextHop sends the decrypted payload to the next relay in the circuit
func (ch *CircuitHandler) forwardToNextHop(ctx context.Context, nextHopURL string, payload []byte, originalSenderKey *btcec.PublicKey, sessionID string) error {
	// Get or create a connection specifically for this session
	relay, err := ch.getConnectionForSession(ctx, nextHopURL, sessionID)
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
			SenderPubKey:    originalSenderKey.SerializeCompressed(),
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
		ch.closeConnectionForSession(nextHopURL, sessionID)

		// Try to get a new connection
		relay, err = ch.getConnectionForSession(ctx, nextHopURL, sessionID)
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

// getConnection gets or creates a WebSocket connection to a relay
func (ch *CircuitHandler) getConnection(ctx context.Context, relayURL string) (*nostr.Relay, error) {
	// Check if we already have a connection to this relay in any session
	ch.mu.RLock()
	// First check if any existing session has this connection
	for _, session := range ch.sessions {
		if session.NextRelayURL == relayURL && session.NextRelay != nil {
			relay := session.NextRelay
			ch.mu.RUnlock()
			return relay, nil
		}
	}
	ch.mu.RUnlock()

	// Create a new connection with timeout
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	newRelay, err := nostr.RelayConnect(connectCtx, relayURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay %s: %w", relayURL, err)
	}

	log.Printf("Created new connection to relay: %s", relayURL)
	return newRelay, nil
}

// Close closes all connections
func (ch *CircuitHandler) Close() {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	// Close all connections in sessions
	for _, session := range ch.sessions {
		if session.NextRelay != nil {
			session.NextRelay.Close()
			session.NextRelay = nil
		}
		if session.PreviousRelay != nil {
			session.PreviousRelay.Close()
			session.PreviousRelay = nil
		}
	}
}

// getConnectionForSession gets or creates a WebSocket connection specifically for a session
func (ch *CircuitHandler) getConnectionForSession(ctx context.Context, relayURL, sessionID string) (*nostr.Relay, error) {
	ch.mu.Lock()
	session, exists := ch.sessions[sessionID]
	if !exists {
		ch.mu.Unlock()
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	// Check if we already have a connection to this relay for this specific session
	if session.NextRelayURL == relayURL && session.NextRelay != nil {
		relay := session.NextRelay
		ch.mu.Unlock()
		return relay, nil
	}
	ch.mu.Unlock()

	// Create a new connection with timeout
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	newRelay, err := nostr.RelayConnect(connectCtx, relayURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay %s: %w", relayURL, err)
	}

	// Store the connection in the session
	ch.mu.Lock()
	session.NextRelay = newRelay
	session.NextRelayURL = relayURL
	ch.mu.Unlock()

	log.Printf("Created new connection for session %s to relay: %s", sessionID, relayURL)
	return newRelay, nil
}

// closeConnectionForSession closes and removes a connection for a specific session
func (ch *CircuitHandler) closeConnectionForSession(relayURL, sessionID string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	session, exists := ch.sessions[sessionID]
	if !exists {
		return
	}

	if session.NextRelayURL == relayURL && session.NextRelay != nil {
		session.NextRelay.Close()
		session.NextRelay = nil
		session.NextRelayURL = ""
	}
}
