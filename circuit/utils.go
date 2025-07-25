package circuit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// EncodeOnionPacketToEventContent encodes an onion packet as hex for Nostr event content
func EncodeOnionPacketToEventContent(packet interface{}) (string, error) {
	packetBytes, err := json.Marshal(packet)
	if err != nil {
		return "", fmt.Errorf("failed to marshal onion packet: %w", err)
	}

	return hex.EncodeToString(packetBytes), nil
}

// DecodeOnionPacketFromEventContent decodes an onion packet from Nostr event content (hex)
func DecodeOnionPacketFromEventContent(content string, packet interface{}) error {
	packetBytes, err := hex.DecodeString(content)
	if err != nil {
		return fmt.Errorf("failed to decode onion packet: %w", err)
	}

	return json.Unmarshal(packetBytes, packet)
}
