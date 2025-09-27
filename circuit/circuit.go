package circuit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lescuer97/shallot/sphinx"
	"github.com/nbd-wtf/go-nostr"
)

const OnionMsgKind int = 720

var (
	ErrNoOnionContent       = errors.New("no onion content")
	ErrUnknownCellCommand   = errors.New("Error. Unknown cell command")
	ErrCircuitAlreadyExists = errors.New("Circuit already exists")
	ErrCircuitDoesntExists  = errors.New("Circuit doesn't exists")
)

type CircuitId = [4]byte
type CircuitHandler struct {
	circuits        map[CircuitId]Circuit
	relayConnection map[string]*nostr.Relay
	generalKey      *sphinx.Sphinx
}

func NewCircuitHandler() (CircuitHandler, error) {
	sphinx, err := sphinx.NewSphinx()
	if err != nil {
		return CircuitHandler{}, err
	}
	return CircuitHandler{
		circuits:        make(map[CircuitId]Circuit),
		relayConnection: make(map[string]*nostr.Relay),
		generalKey:      sphinx,
	}, nil
}

func (c *CircuitHandler) ProcessNostrEvent(evt *nostr.Event) (bool, *sphinx.CellCommand, *sphinx.RelayCommand, error) {
	isFinalStep := false
	if evt.Kind != OnionMsgKind {
		return isFinalStep, nil, nil, ErrNoOnionContent
	}
	cborUnmarshaller := sphinx.GetCBORStrictUnmarshaller()

	//INFO: Get HEX value into bytes
	contentBytes, err := hex.DecodeString(evt.Content)
	if err != nil {
		return isFinalStep, nil, nil, fmt.Errorf("hex.DecodeString(evt.Content). %w", err)
	}

	cell := sphinx.Cell{}
	err = cborUnmarshaller.Unmarshal(contentBytes, &cell)
	if err != nil {
		return isFinalStep, nil, nil, fmt.Errorf("cborUnmarshaller.Unmarshal(contentBytes, &cell). %w", err)
	}

	switch cell.Cmd {
	case sphinx.Create:
		createCell := sphinx.CreateCircuitCell{}
		err = cborUnmarshaller.Unmarshal(contentBytes, &createCell)
		if err != nil {
			return isFinalStep, nil, nil, fmt.Errorf("cborUnmarshaller.Unmarshal(contentBytes, &createCell). %w", err)
		}
		nextHopCreateCircuit, err := c.processCreateCell(createCell)
		if err != nil {
			return isFinalStep, nil, nil, fmt.Errorf("c.processCreateCell(createCell). %w", err)
		}

		if nextHopCreateCircuit == nil {
			isFinalStep = true
			return isFinalStep, &cell.Cmd, nil, nil
		}

		err = c.sendCreateCircuitToNextHop(nextHopCreateCircuit)
		if err != nil {
			return isFinalStep, nil, nil, fmt.Errorf("c.processCreateCell(createCell). %w", err)
		}
		return isFinalStep, &cell.Cmd, nil, nil
	case sphinx.Relay_CMD:
		nextHopRelay, err := c.processRelayCell(cell)
		if err != nil {
			return isFinalStep, nil, nil, fmt.Errorf("c.processRelayCell(cell). %w", err)
		}

		if nextHopRelay == nil {
			isFinalStep = true
			return isFinalStep, &cell.Cmd, nil, nil
		}

		err = c.sendCellToNextHop(nextHopRelay)
		if err != nil {
			return isFinalStep, nil, nil, fmt.Errorf("c.processCreateCell(createCell). %w", err)
		}
		return isFinalStep, &cell.Cmd, nil, nil
	case sphinx.Destroy:
		log.Panicf("still not implemented destroying messages")
	default:
		return isFinalStep, nil, nil, fmt.Errorf("unkown onion relay command")
	}

	return isFinalStep, nil, nil, fmt.Errorf("could not process the relay command")
}

func (c *CircuitHandler) GetGeneralKey() *sphinx.Sphinx {
	return c.generalKey
}

func (c *CircuitHandler) sendCellToNextHop(cell *sphinx.Cell) error {
	if cell == nil {
		return fmt.Errorf("create circuit cell is nil")
	}
	unmarshaller := sphinx.GetCBORStrictEncoder()
	payload, err := unmarshaller.Marshal(cell)
	if err != nil {
		return err
	}

	err = c.sendPayloadToNextHop(payload, cell.Id)
	if err != nil {
		return err
	}

	return nil
}
func (c *CircuitHandler) sendCreateCircuitToNextHop(cell *sphinx.CreateCircuitCell) error {
	if cell == nil {
		return fmt.Errorf("create circuit cell is nil")
	}
	unmarshaller := sphinx.GetCBORStrictEncoder()
	payload, err := unmarshaller.Marshal(cell)
	if err != nil {
		return err
	}

	err = c.sendPayloadToNextHop(payload, cell.Id)
	if err != nil {
		return err
	}

	return nil
}

func (c *CircuitHandler) sendPayloadToNextHop(content []byte, circuitId CircuitId) error {
	event := nostr.Event{
		Kind:    OnionMsgKind,
		Content: hex.EncodeToString(content),
	}
	err := event.Sign(c.generalKey.PrivateKey.Key.String())
	if err != nil {
		return err
	}

	circuit, exists := c.circuits[circuitId]
	if !exists {
		return ErrCircuitDoesntExists
	}

	ctx := context.Background()

	// INFO: check if we already are connected to the relay. if not we create it and add the new one.
	relay, exists := c.relayConnection[circuit.NextRelay]
	if !exists || relay == nil {
		relay = nostr.NewRelay(ctx, circuit.NextRelay)
		err = relay.Connect(ctx)
		if err != nil {
			return err
		}
		c.relayConnection[circuit.NextRelay] = relay
	}

	if !relay.IsConnected() {
		err = relay.Connect(ctx)
		if err != nil {
			return err
		}
	}

	log.Printf("\n event %+v", event)
	err = relay.Publish(ctx, event)
	return nil

}

func (c *CircuitHandler) processRelayCell(cell sphinx.Cell) (*sphinx.Cell, error) {
	circuit, exists := c.circuits[cell.Id]
	if !exists {
		return nil, ErrCircuitDoesntExists
	}
	log.Printf("\n cell %+v", cell)

	payload, err := cell.GetPayloadWithoutPadding()
	if err != nil {
		return nil, fmt.Errorf("cell.GetPayloadWithoutPadding(). %w", err)
	}

	decryptedPayload, err := c.generalKey.DecryptPayload(payload, circuit.SenderPubKey)
	if err != nil {
		return nil, fmt.Errorf("c.generalKey.DecryptPayload(payload, circuit.NextRelayPubkey). %w", err)
	}

	if circuit.NextRelay == "" {
		log.Println("is last hop should have a relay payload")
		cborUnmarshaller := sphinx.GetCBORStrictUnmarshaller()
		var relayPayload sphinx.RelayPayload
		err = cborUnmarshaller.Unmarshal(decryptedPayload, &relayPayload)
		if err != nil {
			return nil, fmt.Errorf("cborUnmarshaller.Unmarshal(decryptedPayload, &relayPayload). %w", err)
		}

		log.Printf("\n relayPayload: %+v", relayPayload)
		return nil, nil
	}

	newCell := sphinx.Cell{Id: circuit.Id, Cmd: cell.Cmd}
	err = newCell.SetPayloadAndAddPadding(decryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("newCell.SetPayloadAndAddPadding(decryptedPayload). %w", err)
	}
	return &newCell, nil
}

func (c *CircuitHandler) processCreateCell(cell sphinx.CreateCircuitCell) (*sphinx.CreateCircuitCell, error) {
	_, exists := c.circuits[cell.Id]
	if exists {
		return nil, ErrCircuitAlreadyExists
	}
	log.Printf("\n cell %+v", cell)

	payload, err := c.generalKey.ParseCreateCircuitCellPayload(cell)
	if err != nil {
		return nil, fmt.Errorf("c.generalKey.ParseCreateCircuitCellPayload(cell). %w", err)
	}

	newCircuit := Circuit{
		Id:              cell.Id,
		Active:          true,
		NextRelay:       payload.NextRelay,
		NextRelayPubkey: payload.NextRelayPubkey,
		SenderPubKey:    cell.SenderPubkey,
	}

	log.Printf("creating new circuit. %+v", newCircuit)
	c.circuits[newCircuit.Id] = newCircuit
	if payload.NextRelay == "" {
		return nil, nil
	}

	nextHop := sphinx.CreateCircuitCell{
		Cell: sphinx.Cell{
			Id:  cell.Id,
			Cmd: cell.Cmd,
		},
		SenderPubkey: cell.SenderPubkey,
	}

	err = nextHop.SetPayloadAndAddPadding(payload.Payload)
	if err != nil {
		return nil, err
	}

	return &nextHop, nil
}

func (c *CircuitHandler) makeResponse(payload []byte, cellCmd sphinx.CellCommand, circuitId CircuitId) (*sphinx.Cell, error) {
	log.Panicf("responses  in relays are not implemented yet")

	circuit, exists := c.circuits[circuitId]
	if !exists {
		return nil, ErrCircuitDoesntExists
	}

	cell, err := c.generalKey.MakeCellFromPayload(cellCmd, payload, circuit.SenderPubKey)
	if err != nil {
		return nil, err
	}

	return &cell, nil
}

func (c *CircuitHandler) nostrEventIsOnionResponse(event nostr.Event) (bool, *sphinx.Cell, error) {
	if event.Kind != OnionMsgKind {
		return false, nil, nil
	}

	var cell sphinx.Cell
	decoder := sphinx.GetCBORStrictUnmarshaller()
	contentBytes, err := hex.DecodeString(event.Content)
	if err != nil {
		return false, nil, err
	}

	err = decoder.Unmarshal(contentBytes, cell)
	if err != nil {
		return false, nil, err
	}

	circuit, exists := c.circuits[cell.Id]
	if !exists {
		return false, nil, ErrCircuitDoesntExists
	}

	if event.PubKey == hex.EncodeToString(circuit.NextRelayPubkey.SerializeCompressed()) {
		return true, &cell, nil
	}

	return false, &cell, nil
}

// TODO: each circuit should have it's own independent sphinx key.
type Circuit struct {
	Id              CircuitId        `cbor:"i"`
	Active          bool             `cbor:"a"`
	SenderPubKey    *btcec.PublicKey `cbor:"s"`
	NextRelay       string           `cbor:"p"`
	NextRelayPubkey *btcec.PublicKey `cbor:"np"`
	PrevRelay       string           `cbor:"pr"`
}

// MarshalCBOR implements custom CBOR marshaling for Circuit
func (c Circuit) MarshalCBOR() ([]byte, error) {
	// Create a struct with the same fields but with []byte instead of *btcec.PublicKey
	type Alias Circuit
	aux := struct {
		SenderPubKey    []byte `cbor:"s"`
		NextRelayPubkey []byte `cbor:"np"`
		*Alias
	}{
		Alias: (*Alias)(&c),
	}

	if c.SenderPubKey != nil {
		aux.SenderPubKey = c.SenderPubKey.SerializeCompressed()
	}

	if c.NextRelayPubkey != nil {
		aux.NextRelayPubkey = c.NextRelayPubkey.SerializeCompressed()
	}

	return sphinx.GetCBORStrictEncoder().Marshal(aux)
}

// UnmarshalCBOR implements custom CBOR unmarshaling for Circuit
func (c *Circuit) UnmarshalCBOR(data []byte) error {
	type Alias Circuit
	aux := struct {
		SenderPubKey    []byte `cbor:"s"`
		NextRelayPubkey []byte `cbor:"np"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := sphinx.GetCBORStrictUnmarshaller().Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.SenderPubKey != nil {
		pubKey, err := btcec.ParsePubKey(aux.SenderPubKey)
		if err != nil {
			return err
		}
		c.SenderPubKey = pubKey
	}

	if aux.NextRelayPubkey != nil {
		pubKey, err := btcec.ParsePubKey(aux.NextRelayPubkey)
		if err != nil {
			return err
		}
		c.NextRelayPubkey = pubKey
	}

	return nil
}

func NewCircuit() (CircuitHandler, error) {
	sphinx, err := sphinx.NewSphinx()
	if err != nil {
		return CircuitHandler{}, err
	}

	return CircuitHandler{
		generalKey: sphinx,
		circuits:   make(map[CircuitId]Circuit),
	}, nil

}
