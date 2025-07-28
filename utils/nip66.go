// Package utils provides utility functions for the shallot project
package utils

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nbd-wtf/go-nostr"
)

// RelayInfo stores information about a relay discovered via NIP-66
type RelayInfo struct {
	PublicKey          []byte // 32-byte X-only public key as used in Bitcoin Taproot
	RelayURL           string
	SupportsOnionKind  bool
	LastAnnounced      time.Time
}

// QueryNIP66Relays queries a relay for NIP-66 relay announcements
// Returns a map of relay URL to RelayInfo, keeping only the most recent event for each relay
func QueryNIP66Relays(relayURL string) (map[string]RelayInfo, error) {
	fmt.Printf("Querying relay %s for NIP-66 relay announcements...\n", relayURL)
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Connect to relay
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}
	defer relay.Close()
	
	// Create filter for NIP-66 relay discovery events (kind 30166)
	filter := nostr.Filter{
		Kinds: []int{30166},
	}
	
	// Subscribe to events
	sub, err := relay.Subscribe(ctx, []nostr.Filter{filter})
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to NIP-66 events: %w", err)
	}
	defer sub.Unsub()
	
	// Map to store relay information (keyed by relay URL)
	relays := make(map[string]RelayInfo)
	
	// Collect events with timeout
	timeout := time.After(5 * time.Second)
eventLoop:
	for {
		select {
		case event := <-sub.Events:
			if event == nil {
				continue
			}
			
			// Process the NIP-66 event
			relayInfo, err := processNIP66Event(event)
			if err != nil {
				continue
			}
			
			// Update or add relay info (only keep the most recent event for each relay)
			if existing, exists := relays[relayInfo.RelayURL]; !exists || event.CreatedAt.Time().After(existing.LastAnnounced) {
				relays[relayInfo.RelayURL] = relayInfo
			}
			
		case <-sub.EndOfStoredEvents:
			// Break the loop when we receive EOSE (End of Stored Events)
			fmt.Println("Received EOSE, finishing query early")
			break eventLoop
			
		case <-timeout:
			fmt.Println("Timeout reached, finishing query")
			break eventLoop
			
		case <-ctx.Done():
			fmt.Println("Context cancelled, finishing query")
			break eventLoop
		}
	}
	
	return relays, nil
}

// processNIP66Event extracts relay information from a NIP-66 event
func processNIP66Event(event *nostr.Event) (RelayInfo, error) {
	// Parse the public key - it's a 32-byte X-only public key in hex format
	pubKeyBytes, err := hex.DecodeString(event.PubKey)
	if err != nil {
		return RelayInfo{}, fmt.Errorf("failed to decode public key: %w", err)
	}
	
	// Validate that it's a 32-byte X-only public key
	if len(pubKeyBytes) != 32 {
		return RelayInfo{}, fmt.Errorf("invalid public key length: expected 32 bytes, got %d", len(pubKeyBytes))
	}
	
	// Validate that it's a valid X coordinate on the secp256k1 curve
	_, err = secp256k1.ParsePubKey(append([]byte{0x02}, pubKeyBytes...))
	if err != nil {
		return RelayInfo{}, fmt.Errorf("invalid public key: not a valid point on secp256k1 curve")
	}
	
	relayInfo := RelayInfo{
		PublicKey:     pubKeyBytes, // Store the 32-byte X-only public key
		LastAnnounced: event.CreatedAt.Time(),
	}
	
	// Extract relay URL from "d" tag
	relayURL := ""
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "d" {
			relayURL = tag[1]
			break
		}
	}
	
	if relayURL == "" {
		return relayInfo, fmt.Errorf("no relay URL found in d tag")
	}
	
	relayInfo.RelayURL = relayURL
	
	// Check if relay supports onion message kind (720)
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "k" && tag[1] == "720" {
			relayInfo.SupportsOnionKind = true
			break
		}
	}
	
	return relayInfo, nil
}

// GetOnionCapableRelays filters a relay map to return only relays that support onion messages
func GetOnionCapableRelays(relays map[string]RelayInfo) map[string]RelayInfo {
	onionRelays := make(map[string]RelayInfo)
	for url, info := range relays {
		if info.SupportsOnionKind {
			onionRelays[url] = info
		}
	}
	return onionRelays
}
