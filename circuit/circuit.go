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

		log.Printf("\n createCell: %+v", createCell)
		log.Printf("\n senderPublicKey: %+v",  createCell.SenderPubkey.SerializeCompressed())
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
	case sphinx.Relay_CMD:
		log.Panicf("still not relaying messages")
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

func (c *CircuitHandler) sendCreateCircuitToNextHop(cell *sphinx.CreateCircuitCell) error {
	if cell == nil {
		return fmt.Errorf("create circuit cell is nil")
	}
	unmarshaller := sphinx.GetCBORStrictEncoder()
	payload, err := unmarshaller.Marshal(cell)
	if err != nil {
		return err
	}

	event := nostr.Event{
		Kind:    OnionMsgKind,
		Content: hex.EncodeToString(payload),
	}
	err = event.Sign(c.generalKey.PrivateKey.Key.String())
	if err != nil {
		return err
	}

	circuit, exists := c.circuits[cell.Id]
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
		return nil
	}

	if !relay.IsConnected() {
		err = relay.Connect(ctx)
		if err != nil {
			return err
		}
	}

	err = relay.Publish(ctx, event)
	return nil
}

func (c *CircuitHandler) processCreateCell(cell sphinx.CreateCircuitCell) (*sphinx.CreateCircuitCell, error) {
	_, exists := c.circuits[cell.Id]
	if exists {
		return nil, ErrCircuitAlreadyExists
	}

	payload, err := c.generalKey.ParseCreateCircuitCellPayload(cell)
	if err != nil {
		return nil, err
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

func NewCircuits() (CircuitHandler, error) {
	sphinx, err := sphinx.NewSphinx()
	if err != nil {
		return CircuitHandler{}, err
	}

	return CircuitHandler{
		generalKey: sphinx,
		circuits:   make(map[CircuitId]Circuit),
	}, nil

}
