package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func main() {
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

	// Connect to relay
	relayURL := "ws://localhost:10023"
	fmt.Printf("Connecting to relay: %s\n", relayURL)

	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		log.Fatal("Failed to connect to relay:", err)
	}
	defer relay.Close()

	fmt.Printf("Successfully connected to relay!\n")

	// Create a test event
	event := nostr.Event{
		PubKey:    pub,
		CreatedAt: nostr.Now(),
		Kind:      1, // Text note kind
		Tags:      []nostr.Tag{},
		Content:   "Hello from shallot nostr client! This is a test message.",
	}

	// Sign the event
	err = event.Sign(sk)
	if err != nil {
		log.Fatal("Failed to sign event:", err)
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
		log.Printf("Failed to subscribe: %v", err)
		return
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

	fmt.Printf("\nClient test completed!\n")
}
