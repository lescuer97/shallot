package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lescuer97/shallot/sphinx"
	"github.com/lescuer97/shallot/utils"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// Session represents a single onion routing session
// [cbor]
type Session struct {
	ID                   string              // Unique session identifier
	OriginalSenderPubKey []byte              // Original sender's public key
	Relays               []SessionRelay      // All relays in the circuit with their information
	CreatedAt            time.Time           // When the session was created
	OnionPacket          *sphinx.OnionPacket // The original onion packet for decryption
}

// SessionRelay holds information about a relay used in a session
// [cbor]
type SessionRelay struct {
	URL       string // Relay URL
	PublicKey []byte // Relay's public key
}

// SessionManager manages onion routing sessions
// [cbor]
type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

// AddSession adds a new session to the manager
func (sm *SessionManager) AddSession(session *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[session.ID] = session
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, exists := sm.sessions[id]
	return session, exists
}

// RemoveSession removes a session by ID
func (sm *SessionManager) RemoveSession(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, id)
}

func main() {
	// Create a session manager
	sessionManager := NewSessionManager()

	var (
		onion   = flag.Bool("onion", false, "Send as onion-routed message")
		message = flag.String("message", "Hello from shallot nostr client! This is a test message.", "Message content")
	)
	flag.Parse()

	// Generate a new private key for this client
	sk := nostr.GeneratePrivateKey()
	pub, err := nostr.GetPublicKey(sk)
	if err != nil {
		log.Fatal("Failed to get public key:", err)
	}

	// Convert to npub format for display
	npub, err := nip19.EncodePublicKey(pub)
	if err != nil {
		log.Fatal("Failed to encode public key:", err)
	}

	fmt.Printf("Generated client identity:\n")
	fmt.Printf("Public Key: %s\n", pub)
	fmt.Printf("npub: %s\n", npub)
	fmt.Printf("Private Key: %s\n", sk)
	fmt.Println()

	// If sending an onion message, discover relays first
	if *onion {
		ctx := context.Background()
		fmt.Printf("\n=== Discovering NIP-66 Relays ===\n")
		relays, err := utils.QueryNIP66Relays("ws://localhost:4869")
		if err != nil {
			log.Fatal("Failed to query NIP-66 relays:", err)
		}

		// Check if there are any relays available
		if len(relays) == 0 {
			log.Panic("No relays found via NIP-66 discovery")
		}

		// Filter for onion-capable relays
		onionRelays := utils.GetOnionCapableRelays(relays)

		// Check if there are any onion-capable relays
		if len(onionRelays) == 0 {
			log.Panic("No onion-capable relays found via NIP-66 discovery")
		}

		// Pick the first two relays (or just one if only one is available)
		var relaysList []struct {
			URL  string
			Info utils.RelayInfo
		}
		relayCount := 0

		for url, relayInfo := range onionRelays {
			relaysList = append(relaysList, struct {
				URL  string
				Info utils.RelayInfo
			}{URL: url, Info: relayInfo})

			relayCount++
			if relayCount >= 2 {
				break
			}
		}

		// Create relay info for each hop in the circuit
		var sphinxRelays []*sphinx.Relay
		var relayURLs []string

		for i, relayData := range relaysList {
			// Convert the 32-byte X-only public key to a full secp256k1 public key
			fullPubKey, err := secp256k1.ParsePubKey(append([]byte{0x02}, relayData.Info.PublicKey...))
			if err != nil {
				log.Fatal("Failed to parse relay public key:", err)
			}

			relayInfo, err := sphinx.NewRelay(fullPubKey, relayData.URL)
			if err != nil {
				log.Fatal("Failed to create relay info:", err)
			}

			sphinxRelays = append(sphinxRelays, relayInfo)
			relayURLs = append(relayURLs, relayData.URL)

			// Print circuit information
			hopName := fmt.Sprintf("Hop %d", i+1)
			if i == len(relaysList)-1 {
				hopName = fmt.Sprintf("Hop %d (Destination)", i+1)
			}
			fmt.Printf("%s: %s\n", hopName, relayData.URL)
		}

		// Connect to the first relay for sending the onion message
		firstHopRelay, err := nostr.RelayConnect(ctx, relayURLs[0])
		if err != nil {
			log.Fatal("Failed to connect to first relay:", err)
		}
		defer firstHopRelay.Close()

		// Convert the message to bytes
		messageBytes := []byte(*message)

		// Create a Sphinx instance for creating the onion packet
		sphinxInstance, err := sphinx.NewSphinx()
		if err != nil {
			log.Fatal("Failed to create sphinx instance:", err)
		}

		// Use the Sphinx module to encode the message through the circuit
		onionPacket, err := sphinxInstance.Encode(messageBytes, sphinxRelays, sphinx.Proxy, "https://localhost:3821")
		if err != nil {
			log.Fatal("Failed to encode message through onion circuit:", err)
		}

		// Create a session for this onion packet
		var sessionRelays []SessionRelay
		for i, relayData := range relaysList {
			sessionRelays = append(sessionRelays, SessionRelay{
				URL:       relayData.URL,
				PublicKey: sphinxRelays[i].PublicKey.SerializeCompressed(),
			})
		}

		session := &Session{
			ID:                   hex.EncodeToString(sphinxInstance.GetPublicKey().SerializeCompressed()),
			OriginalSenderPubKey: sphinxInstance.GetPublicKey().SerializeCompressed(),
			Relays:               sessionRelays,
			CreatedAt:            time.Now(),
			OnionPacket:          onionPacket,
		}

		// Add the session to the session manager
		sessionManager.AddSession(session)

		// Marshal the onion packet to JSON
		packetBytes, err := json.Marshal(onionPacket)
		if err != nil {
			log.Fatal("Failed to marshal onion packet:", err)
		}

		// Convert to hex string for Nostr event content
		content := hex.EncodeToString(packetBytes)

		// Create a Nostr event for the onion message
		event := nostr.Event{
			PubKey:    pub,
			CreatedAt: nostr.Now(),
			Kind:      720, // Onion routing message
			Content:   content,
			Tags: nostr.Tags{
				[]string{"relay", relayURLs[0]},
			},
		}

		// Sign the event
		err = event.Sign(sk)
		if err != nil {
			log.Fatal("Failed to sign onion event:", err)
		}

		err = firstHopRelay.Publish(ctx, event)
		if err != nil {
			log.Fatal("Failed to publish onion event:", err)
		}

		fmt.Printf("✅ Onion event published successfully!\n")

		// Set up subscription to listen for responses
		sub, err := firstHopRelay.Subscribe(ctx, []nostr.Filter{
			{
				Kinds:   []int{720},             // Listen for onion routing messages
				Authors: []string{relayURLs[0]}, // From the relay we sent to
			},
		})
		if err != nil {
			log.Printf("Failed to subscribe to relay: %v", err)
		} else {
			// Handle incoming messages in a separate goroutine
			go handleIncomingMessages(ctx, sub, sessionManager, sphinxInstance)
		}
	} else {
		// Send as regular message using the first discovered relay instead of default
		// First discover relays to get the first one
		relays, err := utils.QueryNIP66Relays("ws://localhost:4869")
		if err != nil {
			log.Fatal("Failed to query relays:", err)
		}

		// Filter for any relay (not just onion-capable for regular messages)
		if len(relays) == 0 {
			log.Panic("No relays found via NIP-66 discovery")
		}

		// Use the first relay in the list
		var firstRelayURL string

		for url := range relays {
			firstRelayURL = url
			break
		}

		fmt.Printf("Using first discovered relay: %s\n", firstRelayURL)

		// Connect to the first relay
		ctx := context.Background()
		firstRelay, err := nostr.RelayConnect(ctx, firstRelayURL)
		if err != nil {
			log.Fatal("Failed to connect to first relay:", err)
		}
		defer firstRelay.Close()

		err = sendRegularMessage(ctx, firstRelay, sk, pub, *message)
		if err != nil {
			log.Fatal("Failed to send regular message:", err)
		}
	}

	fmt.Printf("\nClient test completed!\n")

	// Keep the client running to receive responses
	select {}
}

// sendRegularMessage sends a regular Nostr event
func sendRegularMessage(ctx context.Context, relay *nostr.Relay, sk, pub, message string) error {
	// Create a test event
	event := nostr.Event{
		PubKey:    pub,
		CreatedAt: nostr.Now(),
		Kind:      1, // Text note kind
		Tags:      []nostr.Tag{},
		Content:   message,
	}

	// Sign the event
	err := event.Sign(sk)
	if err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}

	err = relay.Publish(ctx, event)
	if err != nil {
		fmt.Printf("❌ Event publishing failed: %v\n", err)
	} else {
		fmt.Printf("✅ Event published successfully!\n")
	}

	sub, err := relay.Subscribe(ctx, []nostr.Filter{
		{
			IDs: []string{event.ID},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	// Wait for events with timeout
	select {
	case receivedEvent := <-sub.Events:
		if receivedEvent.ID == event.ID {
			fmt.Printf("🎉 Event IDs match - round trip successful!\n")
		}
	case <-time.After(3 * time.Second):
		fmt.Printf("⏰ Timeout waiting for event retrieval\n")
	}

	sub.Unsub()
	return nil
}

// handleIncomingMessages processes incoming onion routing messages
func handleIncomingMessages(ctx context.Context, sub *nostr.Subscription, sessionManager *SessionManager, sphinxInstance sphinx.Sphinx) {
	for {
		select {
		case event := <-sub.Events:
			// Process the incoming event
			if err := processIncomingEvent(event, sessionManager, sphinxInstance); err != nil {
				log.Printf("Error processing incoming event: %v", err)
			}
		case <-ctx.Done():
			// Context cancelled, stop processing
			return
		}
	}
}

// processIncomingEvent handles a single incoming Nostr event
func processIncomingEvent(event *nostr.Event, sessionManager *SessionManager, sphinxInstance sphinx.Sphinx) error {
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

	// Get the session for this packet
	sessionID := hex.EncodeToString(packet.Header.SenderPubKey)
	session, exists := sessionManager.GetSession(sessionID)
	if !exists {
		return fmt.Errorf("no session found for incoming packet with sender key: %s", sessionID)
	}

	// Decrypt the onion layer using the session's original onion packet
	nextHopURL, payload, err := sphinxInstance.Decode(session.OnionPacket)
	if err != nil {
		return fmt.Errorf("failed to decode onion packet: %w", err)
	}

	log.Printf("Decoded onion packet. Next hop: %s, Is final: %t", nextHopURL, nextHopURL == "")

	// If this is the final destination, process the inner payload
	if nextHopURL == "" {
		log.Printf("Reached final destination. Decrypted payload: %s", string(payload))
		// Here you would process the final payload as needed
		return nil
	}

	// If there's a next hop, we would forward the message
	// (Implementation would depend on your specific requirements)
	log.Printf("Message needs to be forwarded to: %s", nextHopURL)

	return nil
}
