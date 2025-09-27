package main

import (
	"context"
	"encoding/hex"
	"log"
	"time"

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
		relaysList = append(relaysList, sphinx.NostrRelay{Url: url, Pubkey: relayInfo.PublicKey})

		relayCount++
		if relayCount >= 3 {
			break
		}
	}
	if relayCount == 0 {
		log.Panicf("could not get any relays that support onion messaging ")
	}

	log.Printf("\n relaysList: %+v", relaysList)

	// First create a circuit relay
	relay := nostr.NewRelay(context.Background(), relaysList[len(relaysList)-1].Url)
	err = relay.Connect(context.Background())
	if err != nil {
		log.Panicf("relay.Connect(context.Background()). %v", err)
	}

	createCircuitCell, err := sphinxKey.MakeCreateCircuitCell(relaysList)
	if err != nil {
		log.Printf("could not make circuit payload. %v", err)
	}

	createCircuitBytes, err := cbor.Marshal(createCircuitCell)
	if err != nil {
		log.Panicf("cbor.Marshal(createCircuitCell). %v", err)
	}

	log.Printf("snederPublicKey: %x", sphinxKey.PublicKey.SerializeCompressed())
	onionEvent := nostr.Event{Kind: circuit.OnionMsgKind, Content: hex.EncodeToString(createCircuitBytes)}
	err = onionEvent.Sign(hex.EncodeToString(sphinxKey.PrivateKey.Serialize()))
	if err != nil {
		log.Panicf("could not sign onion event. %v", err)
	}

	err = relay.Publish(context.Background(), onionEvent)
	if err != nil {
		log.Printf("could not publish event kind")
	}

	time.Sleep(2 * time.Second)
	log.Printf("making message to send to relay")
	relayCell, err := sphinxKey.MakeRelayCircuitCell(createCircuitCell.Id, relaysList, []byte("test"), sphinx.Store)
	if err != nil {
		log.Printf("could not make circuit payload. %v", err)
	}
	relayCellBytes, err := cbor.Marshal(relayCell)
	if err != nil {
		log.Panicf("cbor.Marshal(relayCell). %v", err)
	}

	relayCellOnionEvent := nostr.Event{Kind: circuit.OnionMsgKind, Content: hex.EncodeToString(relayCellBytes)}
	err = relayCellOnionEvent.Sign(hex.EncodeToString(sphinxKey.PrivateKey.Serialize()))
	if err != nil {
		log.Panicf("could not sign onion event. %v", err)
	}

	err = relay.Publish(context.Background(), relayCellOnionEvent)
	if err != nil {
		log.Printf("could not publish event kind")
	}

}
