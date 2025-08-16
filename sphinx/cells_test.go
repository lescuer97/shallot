package sphinx

import (
	"testing"
)

func TestCmdCreatePayload3Relays(t *testing.T) {
	clientSphinx, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make clientSphinx. %+v", err)
	}

	sphinx1, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx1. %+v", err)
	}
	relay1 := NostrRelay{
		Url:    "ws://localhost:8081",
		Pubkey: sphinx1.PublicKey,
	}

	sphinx2, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx2. %+v", err)
	}
	relay2 := NostrRelay{
		Url:    "ws://localhost:8082",
		Pubkey: sphinx2.PublicKey,
	}

	sphinx3, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx3. %+v", err)
	}
	relay3 := NostrRelay{
		Url:    "ws://localhost:8083",
		Pubkey: sphinx3.PublicKey,
	}

	cell, err := clientSphinx.MakeCreateCircuitCell([]NostrRelay{relay3, relay2, relay1})
	if err != nil {
		t.Fatalf("could not encrypt payload. %+v", err)
	}

	createPayload, err := sphinx1.ParseCreateCircuitCellPayload(cell)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 1. %+v", err)
	}

	if createPayload.NextRelay != relay2.Url {
		t.Errorf("the next relay should be relay2. Is: %v", createPayload.NextRelay)
	}

	cell = CreateCircuitCell{
		Cell: Cell{
			Id:  cell.Id,
			Cmd: cell.Cmd,
		},
		SenderPubkey: cell.SenderPubkey,
	}
	err = cell.SetPayloadAndAddPadding(createPayload.Payload)
	if err != nil {
		t.Fatalf("could not add payload and padding. %+v", err)
	}

	createPayload, err = sphinx2.ParseCreateCircuitCellPayload(cell)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 2. %+v", err)
	}

	if createPayload.NextRelay != relay3.Url {
		t.Errorf("the next relay should be relay3. Is: %v", createPayload.NextRelay)
	}

	cell = CreateCircuitCell{
		Cell: Cell{
			Id:  cell.Id,
			Cmd: cell.Cmd,
		},
		SenderPubkey: cell.SenderPubkey,
	}

	err = cell.SetPayloadAndAddPadding(createPayload.Payload)
	if err != nil {
		t.Fatalf("could not add payload and padding. %+v", err)
	}

	createPayload, err = sphinx3.ParseCreateCircuitCellPayload(cell)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 2. %+v", err)
	}

	if createPayload.NextRelay != "" {
		t.Errorf("the next relay should be empty. Is: %v", createPayload.NextRelay)
	}
	if createPayload.NextRelayPubkey != nil {
		t.Errorf("public key should have been empty. Is: %v", createPayload.NextRelay)
	}
	if createPayload.Payload != nil {
		t.Errorf("payload should be nil. Is: %v", createPayload.NextRelay)
	}

}

func TestDecryptIncorrectOrderFailure(t *testing.T) {

	clientSphinx, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make clientSphinx. %+v", err)
	}

	sphinx1, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx1. %+v", err)
	}
	relay1 := NostrRelay{
		Url:    "ws://localhost:8081",
		Pubkey: sphinx1.PublicKey,
	}

	sphinx2, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx2. %+v", err)
	}
	relay2 := NostrRelay{
		Url:    "ws://localhost:8082",
		Pubkey: sphinx2.PublicKey,
	}

	sphinx3, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx3. %+v", err)
	}
	relay3 := NostrRelay{
		Url:    "ws://localhost:8083",
		Pubkey: sphinx3.PublicKey,
	}

	cell, err := clientSphinx.MakeCreateCircuitCell([]NostrRelay{relay3, relay2, relay1})
	if err != nil {
		t.Fatalf("could not encrypt payload. %+v", err)
	}

	createPayload, err := sphinx2.ParseCreateCircuitCellPayload(cell)
	if err == nil {
		t.Errorf("There should have been an error while trying to decrypt the payload. %v. payload: %+v", err, createPayload)
	}
}

func TestCmdRelayCellCommand3Relays(t *testing.T) {

	clientSphinx, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make clientSphinx. %+v", err)
	}

	sphinx1, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx1. %+v", err)
	}
	relay1 := NostrRelay{
		Url:    "ws://localhost:8081",
		Pubkey: sphinx1.PublicKey,
	}

	sphinx2, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx2. %+v", err)
	}
	relay2 := NostrRelay{
		Url:    "ws://localhost:8082",
		Pubkey: sphinx2.PublicKey,
	}

	sphinx3, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx3. %+v", err)
	}
	relay3 := NostrRelay{
		Url:    "ws://localhost:8083",
		Pubkey: sphinx3.PublicKey,
	}

	id, err := generateCryptoID()
	if err != nil {
		t.Fatalf("could not generate random id. %+v", err)
	}
	payload := "hello world"

	cell, err := clientSphinx.MakeRelayCircuitCell(id, []NostrRelay{relay3, relay2, relay1}, []byte(payload), Store)
	if err != nil {
		t.Fatalf("could not encrypt payload. %+v", err)
	}

	createPayload, err := sphinx1.DecryptPayload(cell.Payload[:cell.Length], clientSphinx.PublicKey)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 1. %+v", err)
	}

	createPayload, err = sphinx2.DecryptPayload(createPayload, clientSphinx.PublicKey)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 2. %+v", err)
	}

	createPayload, err = sphinx3.DecryptPayload(createPayload, clientSphinx.PublicKey)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 3. %+v", err)
	}

	strictCbor := GetCBORStrictUnmarshaller()

	var relayPayload RelayPayload
	err = strictCbor.Unmarshal(createPayload, &relayPayload)
	if err != nil {
		t.Fatalf("could not unmarshall relay payload. %+v", err)
	}

	if string(relayPayload.Payload[:]) != payload {
		t.Errorf("unpadded payload was  not correct. Should have been %v. IS: %+v", payload, relayPayload)
	}

}
