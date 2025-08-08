package circuit

import (
	"testing"

	"github.com/lescuer97/shallot/sphinx"
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
