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

func (c *CircuitHandler) getGeneralKey() *sphinx.Sphinx {
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

func (c *CircuitHandler) ProcessCell(cell sphinx.Cell, rawPayload []byte) error {
	unmarshaller := sphinx.GetCBORStrictUnmarshaller()
	switch cell.Cmd {
	case sphinx.Create:
		var createCircuitCell sphinx.CreateCircuitCell
		err := unmarshaller.Unmarshal(rawPayload, &createCircuitCell)
		if err != nil {
			return err
		}

		nextHopCreateCell, err := c.processCreateCell(createCircuitCell)
		if err != nil {
			return nil
		}

		if nextHopCreateCell == nil {
			return nil
		}
		return nil
	case sphinx.Relay_CMD:
		log.Panicf("Still not implemented relay_cmd")
	case sphinx.Destroy:
		log.Panicf("still not implemented destroy")

	default:
		return ErrUnknownCellCommand

	}

	return nil
}

func (c *CircuitHandler) makeResponse(payload []byte, cellCmd sphinx.CellCommand, circuitId CircuitId) (*sphinx.Cell, error) {

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

func (c *CircuitHandler) nostrEventIsOnionResponse(event nostr.Event) (bool,*sphinx.Cell,  error) {
	if event.Kind != OnionMsgKind {
		return false, nil, nil
	}

	var cell sphinx.Cell
	decoder := sphinx.GetCBORStrictUnmarshaller()
	contentBytes, err := hex.DecodeString(event.Content)
	if err != nil {
		return false,nil, err
	}

	err = decoder.Unmarshal(contentBytes, cell)
	if err != nil {
		return false,nil, err
	}

	circuit, exists := c.circuits[cell.Id]
	if !exists {
		return false,nil, ErrCircuitDoesntExists
	}

	if event.PubKey == hex.EncodeToString(circuit.NextRelayPubkey.SerializeCompressed()){
		return true, &cell,  nil
	}

	return false, &cell, nil
}


// TODO: each circuit should have it's own independent sphinx key.
type Circuit struct {
	Id              CircuitId          `cbor:"i"`
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

