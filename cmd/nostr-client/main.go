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
		onionPacket, err := sphinxInstance.Encode(messageBytes, sphinxRelays)
		if err != nil {
			log.Fatal("Failed to encode message through onion circuit:", err)
		}

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
