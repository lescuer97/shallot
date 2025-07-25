package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/lescuer97/shallot/circuit"
	"github.com/lescuer97/shallot/sphinx"
	"github.com/nbd-wtf/go-nostr"
)

func main() {
	// Parse command line flags
	var (
		port      = flag.String("port", "10023", "Port to listen on")
		relayName = flag.String("name", "shallot", "Name of the relay")
	)
	flag.Parse()

	relay := khatru.NewRelay()

	sphinx, err := sphinx.NewSphinx()
	if err != nil {
		log.Panicf("could not generate sphinx keys: %v", err)
	}

	// Initialize the circuit handler
	circuitHandler := circuit.NewCircuitHandler(sphinx)

	// Ensure we close all connections when the program exits
	defer circuitHandler.Close()

	relay.Info.Name = *relayName
	relay.Info.Description = "This is an onion capable relay"
	relay.Info.PubKey = hex.EncodeToString(sphinx.GetPublicKey().SerializeCompressed())
	relay.Info.Contact = "_"
	policies.ApplySaneDefaults(relay)

	store := make(map[string]*nostr.Event, 120)
	relay.StoreEvent = append(relay.StoreEvent,
		func(ctx context.Context, event *nostr.Event) error {
			log.Printf("nostEvent. %+v", event)
			store[event.ID] = event
			return nil
		},
	)
	relay.QueryEvents = append(relay.QueryEvents,
		func(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
			ch := make(chan *nostr.Event)
			go func() {
				for _, evt := range store {
					if filter.Matches(evt) {
						ch <- evt
					}
				}
				close(ch)
			}()
			return ch, nil
		},
	)

	// Add onion message handling logic
	relay.StoreEvent = append(relay.StoreEvent,
		func(ctx context.Context, event *nostr.Event) error {
			// Handle onion routing messages (kind 720)
			if event.Kind == 720 {
				log.Printf("Received onion routing message. Processing...")

				// Pass the event to our circuit handler
				err := circuitHandler.HandleOnionEvent(ctx, event)
				if err != nil {
					log.Printf("Error handling onion event: %v", err)
					// We don't return the error here because we still want to acknowledge receipt
					// but we've logged the error for debugging
				}

				// For onion routing messages, we don't store them in our local store
				// They are just forwarded through the circuit
				return nil
			}

			// For non-onion events, continue with normal processing
			return nil
		},
	)

	// Set up HTTP handlers
	mux := relay.Router()
	// set up other http handlers
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html")
		fmt.Fprintf(w, `<b>welcome</b> to my onion-capable relay!`)
	})

	// Generate and publish NIP-66 relay discovery event
	relayURL := fmt.Sprintf("ws://localhost:%s", *port)
	publishRelayDiscoveryEvent(sphinx, relayURL)

	// Start the server
	address := ":" + *port
	fmt.Printf("Starting relay '%s' on %s\n", *relayName, address)

	// Create a channel to listen for interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		err = http.ListenAndServe(address, relay)
		if err != nil {
			log.Panicf("could not listen to server: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-sigChan
	fmt.Println("\nShutting down relay...")

	// Close the circuit handler connections
	circuitHandler.Close()
	fmt.Println("Relay shutdown complete.")
}

// publishRelayDiscoveryEvent creates and publishes a NIP-66 relay discovery event
func publishRelayDiscoveryEvent(sphinx sphinx.Sphinx, relayURL string) {

	// Create the relay discovery event (kind 30166)
	event := nostr.Event{
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      30166,
		Content:   "{}", // Empty content as per NIP-66 specification
		Tags: nostr.Tags{
			[]string{"r", "ws://127.0.0.1:4869"}, // Relay URL
			[]string{"d", relayURL},              // Relay URL
			[]string{"N", "66"},                  // Supports NIP-66
			[]string{"k", "720"},                 // Supports onion routing events
			[]string{"R", "!payment"},            // No payment required
		},
	}

	// Sign the event
	err := event.Sign(hex.EncodeToString(sphinx.PrivateKey.Serialize()))
	if err != nil {
		log.Printf("Error signing relay discovery event: %v", err)
		return
	}

	fmt.Printf("\n=== NIP-66 Relay Discovery Event ===\n")
	fmt.Printf("Relay URL: %s\n", relayURL)
	fmt.Printf("Event JSON:\n%+v\n", event)
	fmt.Printf("=====================================\n\n")

	// Publish to local relay
	publishToLocalRelay(event)
}

// publishToLocalRelay sends the discovery event to the local relay
func publishToLocalRelay(event nostr.Event) {
	localRelayURL := "ws://127.0.0.1:4869"

	fmt.Printf("Publishing NIP-66 event to local relay: %s\n", localRelayURL)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to local relay
	localRelay, err := nostr.RelayConnect(ctx, localRelayURL)
	if err != nil {
		fmt.Printf("Warning: Could not connect to local relay %s: %v\n", localRelayURL, err)
		return
	}
	defer localRelay.Close()

	log.Printf("\n isConnected %+v", localRelay.IsConnected())
	// Publish the event
	err = localRelay.Publish(ctx, event)
	if err != nil {
		fmt.Printf("Warning: Failed to publish to local relay: %v\n", err)
		return
	}

	fmt.Printf("✅ Successfully published NIP-66 event to local relay\n")
}
