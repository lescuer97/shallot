package main

import (
	"context"
	"encoding/hex"
	"log"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/lescuer97/shallot/circuit"
	"github.com/lescuer97/shallot/sphinx"
	"github.com/lescuer97/shallot/utils"
	"github.com/nbd-wtf/go-nostr"
)

func main() {
	sphinxKey, err := sphinx.NewSphinx()
	if err != nil {
		log.Panicf("sphinx.NewSphinx(). %+v", err)
	}
	// nostr.N

	relays, err := utils.QueryNIP66Relays("ws://localhost:4869")
	if err != nil {
		panic(err)
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
	var relaysList []sphinx.NostrRelay

	relayCount := 0

	for url, relayInfo := range onionRelays {
		relaysList = append(relaysList, sphinx.NostrRelay{Url: url,Pubkey: relayInfo.PublicKey })

		relayCount++
		if relayCount >= 2 {
			break
		}
	}
	if relayCount == 0 {
		log.Panicf("could not get any relays that support onion messaging ")
	}

	log.Printf("\n relaysList: %+v", relaysList)
	organizedRelays := relaysList
	slices.Reverse(organizedRelays)

	log.Printf("\n organizedRelays: %+v", organizedRelays)

	// First create a circuit relay
	relay := nostr.NewRelay(context.Background(), organizedRelays[0].Url)
	err = relay.Connect(context.Background())
	if err != nil {
		log.Panicf("relay.Connect(context.Background()). %v", err)
	}

	createCircuitCell, err := sphinxKey.MakeCreateCircuitCell(relaysList)
	if err != nil {
		log.Printf("could not make circuit payload. %v", err)
	}


	// encoder := sphinx.GetCBORStrictEncoder()
	createCircuitBytes, err := cbor.Marshal(createCircuitCell)
	if err != nil {
		log.Panicf("relay.Connect(context.Background()). %v", err)
	}
	// log.Printf("createCircuitByes %x", createCircuitBytes)

	log.Printf("snederPublicKey: %x", sphinxKey.PublicKey.SerializeCompressed())
	onionEvent := nostr.Event{Kind:circuit.OnionMsgKind, Content: hex.EncodeToString(createCircuitBytes) }
	// log.Printf("onionEvent %+v", onionEvent)

	err = onionEvent.Sign(hex.EncodeToString(sphinxKey.PrivateKey.Serialize()))
	if err != nil {
		log.Panicf("could not sign onion event. %v", err)
	}

	err = relay.Publish(context.Background(), onionEvent)
	if err != nil {
		log.Printf("could not publish event kind")
	}

}
