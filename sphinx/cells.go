package sphinx

import (
	"errors"
	"fmt"
	"log"

	"crypto/rand"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fxamacker/cbor/v2"
)

var (
	ErrorLengthLongerThanPayload = errors.New("length to take is bigger that slice")
)

const (
	MaxPacketSize = 6 * 1024 // 12KB maximum packet size
)

type CellCommand byte

const (
	Create    CellCommand = iota
	Relay_CMD CellCommand = iota + 1
	Destroy   CellCommand = iota + 2
)

type RelayCommand byte

const (
	Query         RelayCommand = iota
	Store         RelayCommand = iota + 1
	Relay_Destroy RelayCommand = iota + 2
)

const MaxCellPayloadSize = MaxPacketSize - 7

type Cell struct {
	Id      [4]byte                  `cbor:"i"`
	Cmd     CellCommand              `cbor:"c"`
	Length  uint16                   `cbor:"l"`
	Payload [MaxCellPayloadSize]byte `cbor:"c"`
}

func (c *Cell) Serialize() ([]byte, error) {
	encoder := GetCBORStrictEncoder()
	payload, err := encoder.Marshal(c)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func (c *Cell) SetPayloadAndAddPadding(payload []byte) error {
	paddedContent, err := addPadding(payload, MaxCellPayloadSize)
	if err != nil {
		return err
	}
	c.Length = uint16(len(payload))
	c.Payload = [MaxCellPayloadSize]byte(paddedContent)
	return nil
}

func (c *Cell) GetPayloadWithoutPadding() ([]byte, error) {
	if c.Length > uint16(len(c.Payload)) {
		return nil, ErrorLengthLongerThanPayload
	}

	return c.Payload[:c.Length], nil
}

type CreateCircuitCell struct {
	Cell
	SenderPubkey *btcec.PublicKey `cbor:"s"`
}

type CreateCircuitPayload struct {
	NextRelay       string           `cbor:"n"`
	NextRelayPubkey *btcec.PublicKey `cbor:"np"`
	Payload         []byte           `cbor:"p"`
}

const RelayPayloadMaxSize = MaxPacketSize - 9

type RelayPayload struct {
	RelayCommnad RelayCommand `cbor:"c"`
	Payload      []byte       `cbor:"p"`
}

type NostrRelay struct {
	Url    string           `cbor:"url"`
	Pubkey *btcec.PublicKey `cbor:"pk"`
}

func GetCBORStrictEncoder() cbor.EncMode {
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		log.Fatal(err)
	}
	return encMode
}

func GetCBORStrictUnmarshaller() cbor.DecMode {
	strictDecOptions := cbor.DecOptions{
		// Strict decoding of integers
		IntDec: cbor.IntDecConvertNone,
		// Require maps to have sorted keys
		MapKeyByteString: cbor.MapKeyByteStringForbidden,
		// Strict float handling
		// No extra elements in arrays or maps
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}

	strictDecMode, err := strictDecOptions.DecMode()
	if err != nil {
		log.Fatal(err)
	}
	return strictDecMode
}

func generateCryptoID() ([4]byte, error) {
	var id [4]byte
	_, err := rand.Read(id[:])
	if err != nil {
		return id, err
	}
	return id, nil
}

func (s *Sphinx) MakeCreateCircuitCell(relays []NostrRelay) (CreateCircuitCell, error) {
	strictCbor := GetCBORStrictEncoder()
	if s.PublicKey == nil {
		log.Panicf("sphinx public key should never be nil")
	}

	var encryptedPayload []byte
	for i := range relays {
		// INFO: The index 0 is actually the last hop
		if i == 0 {
			createPayload := CreateCircuitPayload{}

			marshalledPayload, err := strictCbor.Marshal(createPayload)
			if err != nil {
				return CreateCircuitCell{}, err
			}
			encrypted, err := s.EncryptPayload(marshalledPayload, relays[i].Pubkey)
			if err != nil {
				return CreateCircuitCell{}, err
			}

			encryptedPayload = encrypted
			continue
		}

		payload := CreateCircuitPayload{
			NextRelay:       relays[i-1].Url,
			NextRelayPubkey: relays[i-1].Pubkey,
			Payload:         encryptedPayload,
		}

		marshalledPayload, err := strictCbor.Marshal(payload)
		if err != nil {
			return CreateCircuitCell{}, err
		}

		encrypted, err := s.EncryptPayload(marshalledPayload, relays[i].Pubkey)
		if err != nil {
			return CreateCircuitCell{}, err
		}

		encryptedPayload = encrypted
	}

	randomId, err := generateCryptoID()
	if err != nil {
		return CreateCircuitCell{}, err
	}

	cell := CreateCircuitCell{
		Cell: Cell{
			Id:  randomId,
			Cmd: Create,
		},
		SenderPubkey: s.PublicKey,
	}
	err = cell.SetPayloadAndAddPadding(encryptedPayload)
	if err != nil {
		return CreateCircuitCell{}, err
	}

	return cell, nil
}

func (s *Sphinx) ParseCreateCircuitCellPayload(cell CreateCircuitCell) (CreateCircuitPayload, error) {
	decryptedPayload, err := s.DecryptPayload(cell.Payload[:cell.Length], cell.SenderPubkey)
	if err != nil {
		return CreateCircuitPayload{}, err
	}

	strictCbor := GetCBORStrictUnmarshaller()

	var payload CreateCircuitPayload
	err = strictCbor.Unmarshal(decryptedPayload, &payload)
	if err != nil {
		return CreateCircuitPayload{}, err
	}

	return payload, nil
}

func addPadding(data []byte, targetSize int) ([]byte, error) {
	if len(data) > targetSize {
		return nil, fmt.Errorf("data size %d exceeds target size %d", len(data), targetSize)
	}
	paddingSize := targetSize - len(data)
	if paddingSize == 0 {
		return data, nil
	}
	padded := make([]byte, targetSize)
	copy(padded[:len(data)], data)
	// Fill the remaining bytes with cryptographically secure random data
	if _, err := rand.Read(padded[len(data):]); err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	return padded, nil
}

func (s *Sphinx) MakeRelayCircuitCell(circuitId [4]byte, relays []NostrRelay, finalPayload []byte, relayCommand RelayCommand) (Cell, error) {
	strictCbor := GetCBORStrictEncoder()
	if s.PublicKey == nil {
		log.Panicf("sphinx public key should never be nil")
	}

	var encryptedPayload []byte
	for i := range relays {
		// INFO: The index 0 is actually the last hop
		if i == 0 {
			relayPayload := RelayPayload{
				RelayCommnad: relayCommand,
				Payload:      finalPayload,
			}

			marshalledPayload, err := strictCbor.Marshal(relayPayload)
			if err != nil {
				return Cell{}, err
			}
			encrypted, err := s.EncryptPayload(marshalledPayload, relays[i].Pubkey)
			if err != nil {
				return Cell{}, err
			}

			encryptedPayload = encrypted
			continue
		}

		encrypted, err := s.EncryptPayload(encryptedPayload, relays[i].Pubkey)
		if err != nil {
			return Cell{}, err
		}

		encryptedPayload = encrypted
	}

	cell := Cell{
		Id:  circuitId,
		Cmd: Create,
	}

	err := cell.SetPayloadAndAddPadding(encryptedPayload)
	if err != nil {
		return Cell{}, err
	}

	return cell, nil
}
