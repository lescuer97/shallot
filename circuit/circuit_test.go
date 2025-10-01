package circuit

import (
	"encoding/hex"
	"errors"
	"log"
	"testing"

	"github.com/lescuer97/shallot/sphinx"
	"github.com/nbd-wtf/go-nostr"
)

func TestCircuitNextHopDecryption(t *testing.T) {
	clientSphinx, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("could not make clientSphinx. %+v", err)
	}

	relay1CircuitHandler, err := NewCircuitHandler()
	if err != nil {
		t.Fatalf("Could not generate relay handler 1. %+v", err)
	}

	relay1 := sphinx.NostrRelay{
		Url:    "ws://localhost:8081",
		Pubkey: relay1CircuitHandler.generalKey.PublicKey,
	}

	relay2CircuitHandler, err := NewCircuitHandler()
	if err != nil {
		t.Fatalf("Could not generate relay handler 1. %+v", err)
	}

	relay2 := sphinx.NostrRelay{
		Url:    "ws://localhost:8082",
		Pubkey: relay2CircuitHandler.generalKey.PublicKey,
	}

	initialCell, err := clientSphinx.MakeCreateCircuitCell([]sphinx.NostrRelay{relay2, relay1})
	if err != nil {
		t.Fatalf("could not encrypt payload. %+v", err)
	}

	nextCell, err := relay1CircuitHandler.processCreateCell(initialCell)
	if err != nil {
		t.Fatalf("relay circuit 1 could not parse the initialCell. %+v", err)
	}

	finalPayload, err := relay2CircuitHandler.generalKey.ParseCreateCircuitCellPayload(*nextCell)
	if err != nil {
		t.Fatalf("Could not parse final payload from relay %+v", err)
	}

	if finalPayload.NextRelay != "" {
		t.Errorf("next relay is not correct %+v. should be empty", finalPayload.NextRelay)

	}

	if len(finalPayload.Payload) != 0 {
		t.Errorf("there shoulld be no payload on the final relay. %v", finalPayload.Payload)
	}

	finalCell, err := relay2CircuitHandler.processCreateCell(*nextCell)
	if err != nil {
		t.Fatalf("relay circuit 2 could not parse the next cell. %+v", err)
	}

	if finalCell != nil {
		t.Fatalf("final cell should be empty. %+v", err)

	}
}

func TestNostrEventBeingOnionNotCorrectKind(t *testing.T) {
	event := nostr.Event{
		Kind: nostr.KindArticle,
	}

	circuitHandler, err := NewCircuitHandler()
	if err != nil {
		t.Fatalf("Could not generate relay handler. %+v", err)
	}

	isOnion, cell, err := circuitHandler.nostrEventIsOnionResponse(event)
	if isOnion {
		t.Errorf("the event should not be an onion")
	}
	if cell != nil {
		t.Errorf("Cell should be nil becasue processing should not have happened. %+v", cell)
	}
	if err != nil {
		t.Errorf("there should not be an error %+v", err)
	}

}

func TestNostrEventBeingOnionWithNonExistingCircuitId(t *testing.T) {
	circuitHandler, err := NewCircuitHandler()
	if err != nil {
		t.Fatalf("Could not generate relay handler. %+v", err)
	}
	initCell := sphinx.Cell{
		Id: [4]byte{10, 11, 21, 32},
	}
	err = initCell.SetPayloadAndAddPadding([]byte("test"))
	if err != nil {
		t.Fatalf("could not set padding to cell %+v", err)
	}

	cborEnc := sphinx.GetCBORStrictEncoder()
	cellbytes, err := cborEnc.Marshal(initCell)
	if err != nil {
		t.Fatalf("could not create cell bytes %+v", err)
	}
	event := nostr.Event{
		Kind:    OnionMsgKind,
		Content: hex.EncodeToString(cellbytes),
	}

	log.Printf("\n event.kind: %+v", event.Kind)
	_, _, err = circuitHandler.nostrEventIsOnionResponse(event)
	if errors.Is(err, ErrCircuitDoesntExists) {
		t.Errorf("there should be an error about circuit not existing %+v", err)
	}

}
func TestCircuitResponseEndRelay(t *testing.T) {
	clientSphinx, err := sphinx.NewSphinx()
	if err != nil {
		t.Fatalf("could not make clientSphinx. %+v", err)
	}

	relay1CircuitHandler, err := NewCircuitHandler()
	if err != nil {
		t.Fatalf("Could not generate relay handler 1. %+v", err)
	}

	relay1 := sphinx.NostrRelay{
		Url:    "ws://localhost:8081",
		Pubkey: relay1CircuitHandler.generalKey.PublicKey,
	}

	relay2CircuitHandler, err := NewCircuitHandler()
	if err != nil {
		t.Fatalf("Could not generate relay handler 1. %+v", err)
	}

	relay2 := sphinx.NostrRelay{
		Url:    "ws://localhost:8082",
		Pubkey: relay2CircuitHandler.generalKey.PublicKey,
	}

	initialCell, err := clientSphinx.MakeCreateCircuitCell([]sphinx.NostrRelay{relay2, relay1})
	if err != nil {
		t.Fatalf("could not encrypt payload. %+v", err)
	}

	nextCell, err := relay1CircuitHandler.processCreateCell(initialCell)
	if err != nil {
		t.Fatalf("relay circuit 1 could not parse the initialCell. %+v", err)
	}

	finalPayload, err := relay2CircuitHandler.generalKey.ParseCreateCircuitCellPayload(*nextCell)
	if err != nil {
		t.Fatalf("Could not parse final payload from relay %+v", err)
	}

	if finalPayload.NextRelay != "" {
		t.Errorf("next relay is not correct %+v. should be empty", finalPayload.NextRelay)

	}

	if len(finalPayload.Payload) != 0 {
		t.Errorf("there shoulld be no payload on the final relay. %v", finalPayload.Payload)
	}

	finalCell, err := relay2CircuitHandler.processCreateCell(*nextCell)
	if err != nil {
		t.Fatalf("relay circuit 2 could not parse the next cell. %+v", err)
	}

	if finalCell != nil {
		t.Fatalf("final cell should be empty. %+v", err)
	}


	// make the response cell for encryption
	res := sphinx.ResponseCircuitCell{
		Cell: sphinx.Cell{
			Id: finalCell.Id,
			Cmd: sphinx.Response,
		},
		ResponseRelayPubkey: relay2CircuitHandler.generalKey.PublicKey,
	}
	err = res.SetPayloadAndAddPadding([]byte("test"))
	if err != nil {
		t.Fatalf("could not set the payload padding for the response. %+v", err)
	}

	resRelay2, err := relay2CircuitHandler.processResponseCell(res)
	if err != nil {
		t.Fatalf("could not proceess the response cell for relay 2 %+v", err)
	}

	resRelay1, err := relay1CircuitHandler.processResponseCell(*resRelay2)
	if err != nil {
		t.Fatalf("could not proceess the response cell for relay 2 %+v", err)
	}
	 

	
	 // resRelay1.
	// finalResponse, err := sph
	 


	// relay2CircuitHandler.sendResponseToPrevRelay()
}
