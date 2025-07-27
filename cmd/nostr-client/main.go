package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lescuer97/shallot/sphinx"
	"github.com/lescuer97/shallot/utils"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func main() {
	// Parse command line flags
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

	// Default relay URL for initial connection
	relayURL := "ws://localhost:10023"
	fmt.Printf("Connecting to relay: %s\n", relayURL)

	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		log.Fatal("Failed to connect to relay:", err)
	}
	defer relay.Close()

	fmt.Printf("Successfully connected to relay!\n")

	// If sending an onion message, discover relays first
	if *onion {
		fmt.Printf("\n=== Discovering NIP-66 Relays ===\n")
		relays, err := utils.QueryNIP66Relays("ws://localhost:4869")
		if err != nil {
			log.Fatal("Failed to query NIP-66 relays:", err)
		}
		log.Printf("\n relays %+v", relays)

		// Filter for onion-capable relays
		onionRelays := utils.GetOnionCapableRelays(relays)
		
		if len(onionRelays) == 0 {
			log.Fatal("No onion-capable relays found via NIP-66 discovery")
		}

		// Use the first available onion-capable relay
		var firstRelay utils.RelayInfo
		var firstRelayURL string
		for url, relayInfo := range onionRelays {
			firstRelay = relayInfo
			firstRelayURL = url
			break
		}

		fmt.Printf("Using relay %s for onion routing\n", firstRelayURL)
		
		// Send as onion-routed message
		err = sendOnionMessage(ctx, relay, sk, pub, *message, firstRelayURL, firstRelay.PublicKey)
		if err != nil {
			log.Fatal("Failed to send onion message:", err)
		}
	} else {
		// Send as regular message
		err = sendRegularMessage(ctx, relay, sk, pub, *message)
		if err != nil {
			log.Fatal("Failed to send regular message:", err)
		}
	}

	fmt.Printf("\nClient test completed!\n")
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

	fmt.Printf("Created and signed test event:\n")
	fmt.Printf("Event ID: %s\n", event.ID)
	fmt.Printf("Kind: %d\n", event.Kind)
	fmt.Printf("Content: %s\n", event.Content)
	fmt.Printf("Created At: %s\n", time.Unix(int64(event.CreatedAt), 0).Format(time.RFC3339))
	fmt.Println()

	// Publish the event
	fmt.Printf("Publishing event to relay...\n")

	err = relay.Publish(ctx, event)
	if err != nil {
		fmt.Printf("❌ Event publishing failed: %v\n", err)
	} else {
		fmt.Printf("✅ Event published successfully!\n")
	}

	// Try to fetch the event back to verify it was stored
	fmt.Printf("\nAttempting to fetch the event back from relay...\n")

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
		fmt.Printf("✅ Successfully retrieved event from relay!\n")
		fmt.Printf("Retrieved Event ID: %s\n", receivedEvent.ID)
		fmt.Printf("Retrieved Content: %s\n", receivedEvent.Content)
		if receivedEvent.ID == event.ID {
			fmt.Printf("🎉 Event IDs match - round trip successful!\n")
		}
	case <-time.After(3 * time.Second):
		fmt.Printf("⏰ Timeout waiting for event retrieval\n")
	}

	sub.Unsub()
	return nil
}

// sendOnionMessage sends an onion-routed message using the Sphinx module
func sendOnionMessage(ctx context.Context, relay *nostr.Relay, sk, pub, message, relayURL string, relayPubKey []byte) error {
	fmt.Printf("Sending onion-routed message: %s\n", message)
	fmt.Printf("Using relay as single hop: %s\n", relayURL)
	
	// Create a Sphinx instance for creating the onion packet
	sphinxInstance, err := sphinx.NewSphinx()
	if err != nil {
		return fmt.Errorf("failed to create sphinx instance: %w", err)
	}

	// Create a relay info for this relay (acting as the single hop in the circuit)
	// Use the actual relay's public key from NIP-66 discovery
	// Convert the 32-byte X-only public key to a full secp256k1 public key
	fullPubKey, err := secp256k1.ParsePubKey(append([]byte{0x02}, relayPubKey...))
	if err != nil {
		return fmt.Errorf("failed to parse relay public key: %w", err)
	}
	
	relayInfo, err := sphinx.NewRelay(fullPubKey, relayURL)
	if err != nil {
		return fmt.Errorf("failed to create relay info: %w", err)
	}

	// Create a circuit with just this relay as the single hop
	// In a more complex implementation, we would have multiple relays
	relays := []*sphinx.Relay{relayInfo}

	// Convert the message to bytes
	messageBytes := []byte(message)

	// Use the Sphinx module to encode the message through the circuit
	onionPacket, err := sphinxInstance.Encode(messageBytes, relays)
	if err != nil {
		return fmt.Errorf("failed to encode message through onion circuit: %w", err)
	}

	// Marshal the onion packet to JSON
	packetBytes, err := json.Marshal(onionPacket)
	if err != nil {
		return fmt.Errorf("failed to marshal onion packet: %w", err)
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
			[]string{"relay", relayURL},
		},
	}

	// Sign the event
	err = event.Sign(sk)
	if err != nil {
		return fmt.Errorf("failed to sign onion event: %w", err)
	}

	fmt.Printf("Created and signed onion event:\n")
	fmt.Printf("Event ID: %s\n", event.ID)
	fmt.Printf("Kind: %d\n", event.Kind)
	fmt.Printf("Content length: %d characters (hex encoded)\n", len(event.Content))
	fmt.Printf("Created At: %s\n", time.Unix(int64(event.CreatedAt), 0).Format(time.RFC3339))
	fmt.Println()

	// Publish the onion event
	fmt.Printf("Publishing onion event to relay...\n")

	err = relay.Publish(ctx, event)
	if err != nil {
		fmt.Printf("❌ Onion event publishing failed: %v\n", err)
		return fmt.Errorf("failed to publish onion event: %w", err)
	}

	fmt.Printf("✅ Onion event published successfully!\n")
	
	// Note: We don't try to fetch it back since onion events are handled differently
	// and may not be stored in the same way as regular events
	
	return nil
}
