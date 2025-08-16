package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fiatjaf/eventstore/sqlite3"
	"github.com/fiatjaf/khatru"
	// "github.com/fiatjaf/khatru/policies"
	"github.com/lescuer97/shallot/circuit"
	"github.com/lescuer97/shallot/sphinx"
	"github.com/nbd-wtf/go-nostr"
)

func main() {
	port := flag.Int("port", 3334, "port to start the websocket on")
	flag.Parse()
	relay := khatru.NewRelay()

	db := sqlite3.SQLite3Backend{DatabaseURL: "./db"}
	if err := db.Init(); err != nil {
		panic(err)
	}

	circuitHandler, err := circuit.NewCircuitHandler()
	if err != nil {
		log.Panic("could not start the circuit handler. %w", err)
	}

	// policies.ApplySaneDefaults(relay)

	relay.StoreEvent = append(relay.StoreEvent,
	func(ctx context.Context, event *nostr.Event) error {
		// TODO: check if the event is an onion event and if it send it to the circuit manager. if not do a normal
		// operation.
		if event.Kind == circuit.OnionMsgKind {
			isFinal, cellCommand, relayCommand, err := circuitHandler.ProcessNostrEvent(event)
			if err != nil {
				log.Printf("Something went wrong. %+v", err)
			}

			if isFinal && cellCommand == nil {
				log.Panicf("if the last hop is final there should have always been some end command")
			}

			if isFinal && relayCommand != nil {

			}

		} else {
			db.SaveEvent(ctx, event)
		}

		return nil
	},
)
	relay.ReplaceEvent = append(relay.ReplaceEvent,
	func(ctx context.Context, event *nostr.Event) error {
		// TODO: check if the event is an onion event and if it send it to the circuit manager. if not do a normal
		// operation.
		if event.Kind == circuit.OnionMsgKind {
			isFinal, cellCommand, relayCommand, err := circuitHandler.ProcessNostrEvent(event)
			if err != nil {
				log.Printf("Something went wrong. %+v", err)
			}

			if isFinal && cellCommand == nil {
				log.Panicf("if the last hop is final there should have always been some end command")
			}

			if isFinal && relayCommand != nil {

			}

		} else {
			db.SaveEvent(ctx, event)
		}

		return nil
	},
)

	// relay.StoreEvent = append(relay.StoreEvent, db.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, db.QueryEvents)
	relay.CountEvents = append(relay.CountEvents, db.CountEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, db.DeleteEvent)
	relay.ReplaceEvent = append(relay.ReplaceEvent, db.ReplaceEvent)


		// Generate and publish NIP-66 relay discovery event
	relayURL := fmt.Sprintf("ws://localhost:%v", *port)
	publishRelayDiscoveryEvent(circuitHandler.GetGeneralKey(), relayURL)

	portStr := fmt.Sprintf(":%v", *port)
	fmt.Printf("running on %v", portStr)
	http.ListenAndServe(portStr, relay)
}

// publishRelayDiscoveryEvent creates and publishes a NIP-66 relay discovery event
func publishRelayDiscoveryEvent(sphinxInstance *sphinx.Sphinx, relayURL string) {
	// Create the relay discovery event (kind 30166)
	event := nostr.Event{
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      30166, // Relay Discovery event
		Content:   "{}",  // Empty content as per NIP-66 specification
		Tags: nostr.Tags{
			[]string{"d", relayURL},   // Relay URL
			[]string{"N", "66"},       // Supports NIP-66
			[]string{"k", "720"},      // Supports onion routing events
			[]string{"R", "!payment"}, // No payment required
			[]string{"R", "!auth"},    // No authentication required
		},
	}

	// Sign the event
	err := event.Sign(hex.EncodeToString(sphinxInstance.PrivateKey.Serialize()))
	if err != nil {
		log.Printf("Error signing relay discovery event: %v", err)
		return
	}

	fmt.Printf("\n=== NIP-66 Relay Discovery Event ===\n")
	fmt.Printf("Relay URL: %s\n", relayURL)
	fmt.Printf("Event JSON: %+v\n", event)
	fmt.Printf("=====================================\n\n")

	// Publish to local relay
	publishToLocalRelay(event)
}

// publishToLocalRelay sends the discovery event to the local relay
func publishToLocalRelay(event nostr.Event) {
	localRelayURL := "ws://localhost:4869"

	fmt.Printf("Publishing NIP-66 event to local relay: %s\n", localRelayURL)

	// Create context with timeout
	ctx := context.Background()

	// Connect to local relay
	localRelay, err := nostr.RelayConnect(ctx, localRelayURL)
	if err != nil {
		fmt.Printf("Warning: Could not connect to local relay %s: %v\n", localRelayURL, err)
		return
	}
	defer localRelay.Close()

	// Publish the event
	err = localRelay.Publish(ctx, event)
	if err != nil {
		fmt.Printf("Warning: Failed to publish to local relay: %v\n", err)
		return
	}

	fmt.Printf("✅ Successfully published NIP-66 event to local relay\n")
}

