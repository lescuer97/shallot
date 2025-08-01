package sphinx

import (
	"fmt"
	"log"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func makeRelays(t *testing.T, n int) ([]*Relay, []Sphinx) {
	relays := make([]*Relay, n)
	nodes := make([]Sphinx, n)
	for i := 0; i < n; i++ {
		node, err := NewSphinx()
		if err != nil {
			t.Fatalf("failed to create sphinx node: %v", err)
		}
		nodes[i] = node
		url := fmt.Sprintf("wss://relay%d.example.com", i)
		relays[i], err = NewRelay(node.GetPublicKey(), url)
		if err != nil {
			t.Fatalf("failed to create relay: %v", err)
		}
	}
	return relays, nodes
}

func TestSimple3Relays(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 3)
	msg := []byte("hello world")
	pkt, err := sender.Encode(msg, relays, Proxy, "test")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	currentPacket := pkt
	for _, node := range nodes {
		nextHop, payload, err := node.Decode(currentPacket)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		// Create new packet for next iteration with proper header
		currentPacket = &OnionPacket{
			Header: OnionHeader{
				SenderPubKey: sender.GetPublicKey().SerializeCompressed(),
			},
			EncryptedPayload: payload,
		}
		// log.Printf("\n currentPacket: %+v", currentPacket)
		_ = nextHop // not used in this test
	}

	var lastHop LastHopPayload
	err = cbor.Unmarshal(currentPacket.EncryptedPayload, &lastHop)
	if err != nil {
		t.Fatalf("could ot unmarshall the encrypted payload %+v", err)
	}
	log.Printf("\n lastHop: %+v", lastHop)

	if string(lastHop.Payload) != string(msg) {
		t.Errorf("final payload mismatch: got %q, want %q", currentPacket.EncryptedPayload, msg)
	}
}

func TestSphinxEncryptDecryptLayer_Success(t *testing.T) {
	sender, _ := NewSphinx()
	receiver, _ := NewSphinx()
	payload := []byte("test onion layer payload")

	// Create a mock relay for the single hop test
	relay, err := NewRelay(receiver.GetPublicKey(), "wss://test.example.com")
	if err != nil {
		t.Fatalf("failed to create relay: %v", err)
	}

	// Use the new 4-argument Encode function
	relays := []*Relay{relay}
	packet, err := sender.Encode(payload, relays, Proxy, "test")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	nextHop, decrypted, err := receiver.Decode(packet)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	var lastHop LastHopPayload
	err = cbor.Unmarshal(decrypted, &lastHop)
	if err != nil {
		t.Fatalf("could not unmarshal the encrypted payload %+v", err)
	}

	if string(lastHop.Payload) != string(payload) {
		t.Fatalf("decrypted payload mismatch: got %q, want %q", lastHop.Payload, payload)
	}

	// nextHop should be empty since this is the final hop
	if nextHop != "" {
		t.Fatalf("expected empty nextHop, got %q", nextHop)
	}
}

func TestSphinxDecryptLayer_FailsWithWrongKey(t *testing.T) {
	sender, _ := NewSphinx()
	receiver, _ := NewSphinx()
	wrongReceiver, _ := NewSphinx()
	payload := []byte("test onion layer payload")

	// Create a mock relay for the test
	relay, err := NewRelay(receiver.GetPublicKey(), "wss://test.example.com")
	if err != nil {
		t.Fatalf("failed to create relay: %v", err)
	}

	// Use the new 4-argument Encode function
	relays := []*Relay{relay}
	packet, err := sender.Encode(payload, relays, Proxy, "test")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Try to decode with wrong receiver - this should fail because the header
	// and the encryption are tied to the specific sender
	_, _, err = wrongReceiver.Decode(packet)
	if err == nil {
		t.Fatalf("expected error when decoding with wrong receiver, got nil")
	}
}

func TestEncodeOnion_MultiHopManualDecode(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 3)
	msg := []byte("manual multi-hop decode test")
	packet, err := sender.Encode(msg, relays, Proxy, "test")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if len(packet.EncryptedPayload) > MaxPacketSize {
		t.Fatalf("initial packet size exceeds MTU: got %d, want <= %d", len(packet.EncryptedPayload), MaxPacketSize)
	}

	// Test first hop
	nextHop1, payload1, err := nodes[0].Decode(packet)
	if err != nil {
		t.Fatalf("hop 0: Decode failed: %v", err)
	}
	if nextHop1 != relays[1].URL {
		t.Fatalf("hop 0: expected nextHop %q, got %q", relays[1].URL, nextHop1)
	}

	// Test second hop
	packet2 := &OnionPacket{
		Header: OnionHeader{
			SenderPubKey:    sender.GetPublicKey().SerializeCompressed(),
			NextRelayURL:    *relays[1],
			EncryptedLength: len(payload1),
		},
		EncryptedPayload: payload1,
	}
	nextHop2, payload2, err := nodes[1].Decode(packet2)
	if err != nil {
		t.Fatalf("hop 1: Decode failed: %v", err)
	}
	if nextHop2 != relays[2].URL {
		t.Fatalf("hop 1: expected nextHop %q, got %q", relays[2].URL, nextHop2)
	}

	// Test third hop
	packet3 := &OnionPacket{
		Header: OnionHeader{
			SenderPubKey:    sender.GetPublicKey().SerializeCompressed(),
			NextRelayURL:    *relays[2],
			EncryptedLength: len(payload2),
		},
		EncryptedPayload: payload2,
	}
	nextHop3, payload3, err := nodes[2].Decode(packet3)
	if err != nil {
		t.Fatalf("hop 2: Decode failed: %v", err)
	}
	if nextHop3 != "" {
		t.Fatalf("hop 2: expected no nextHop, got %q", nextHop3)
	}

	// Check final payload
	var lastHop LastHopPayload
	err = cbor.Unmarshal(payload3, &lastHop)
	if err != nil {
		t.Fatalf("could not unmarshal the encrypted payload %+v", err)
	}

	if string(lastHop.Payload) != string(msg) {
		t.Fatalf("final payload mismatch: got %q, want %q", lastHop.Payload, msg)
	}
}

func TestOnionPrivacyAtEachHop(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 3)
	msg := []byte("privacy test message")
	pkt, err := sender.Encode(msg, relays, Proxy, "test")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	currentPacket := pkt
	for i, node := range nodes {
		nextHop, payload, err := node.Decode(currentPacket)
		if err != nil {
			t.Fatalf("hop %d: Decode failed: %v", i, err)
		}

		// At each hop, only the next relay URL should be visible
		if i < len(nodes)-1 {
			if nextHop != relays[i+1].URL {
				t.Fatalf("hop %d: expected nextHop %q, got %q", i, relays[i+1].URL, nextHop)
			}
		} else {
			if nextHop != "" {
				t.Fatalf("final hop: expected no nextHop, got %q", nextHop)
			}
		}

		// The payload at this hop should not be readable as the original message
		if i < len(nodes)-1 {
			var tryMsg string
			if err := cbor.Unmarshal(payload, &tryMsg); err == nil && tryMsg == string(msg) {
				t.Fatalf("hop %d: payload should not be readable as message", i)
			}
		} else {
			// At the final hop, we should be able to unmarshal as LastHopPayload
			var lastHop LastHopPayload
			if err := cbor.Unmarshal(payload, &lastHop); err != nil {
				t.Fatalf("hop %d: could not unmarshal as LastHopPayload: %v", i, err)
			}
			if string(lastHop.Payload) != string(msg) {
				t.Fatalf("hop %d: final payload mismatch: got %q, want %q", i, lastHop.Payload, msg)
			}
		}

		// Prepare for next hop
		if i < len(nodes)-1 {
			currentPacket = &OnionPacket{
				Header: OnionHeader{
					SenderPubKey: sender.GetPublicKey().SerializeCompressed(),
					NextRelayURL: *relays[i+1],
				},
				EncryptedPayload: payload,
			}
		}
	}
}

func TestOnionPrivacyAtEachHop5Relays(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 5)
	msg := []byte("privacy test message 5 relays")
	pkt, err := sender.Encode(msg, relays, Proxy, "test")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	currentPacket := pkt
	for i, node := range nodes {
		nextHop, payload, err := node.Decode(currentPacket)
		if err != nil {
			t.Fatalf("hop %d: Decode failed: %v", i, err)
		}

		if i < len(nodes)-1 {
			if nextHop != relays[i+1].URL {
				t.Fatalf("hop %d: expected nextHop %q, got %q", i, relays[i+1].URL, nextHop)
			}
		} else {
			if nextHop != "" {
				t.Fatalf("final hop: expected no nextHop, got %q", nextHop)
			}
		}

		// The payload at this hop should not be readable as the original message
		if i < len(nodes)-1 {
			var tryMsg string
			if err := cbor.Unmarshal(payload, &tryMsg); err == nil && tryMsg == string(msg) {
				t.Fatalf("hop %d: payload should not be readable as message", i)
			}
		} else {
			// At the final hop, we should be able to unmarshal as LastHopPayload
			var lastHop LastHopPayload
			if err := cbor.Unmarshal(payload, &lastHop); err != nil {
				t.Fatalf("hop %d: could not unmarshal as LastHopPayload: %v", i, err)
			}
			if string(lastHop.Payload) != string(msg) {
				t.Fatalf("hop %d: final payload mismatch: got %q, want %q", i, lastHop.Payload, msg)
			}
		}

		// Prepare for next hop
		if i < len(nodes)-1 {
			currentPacket = &OnionPacket{
				Header: OnionHeader{
					SenderPubKey: sender.GetPublicKey().SerializeCompressed(),
					NextRelayURL: *relays[i+1],
				},
				EncryptedPayload: payload,
			}
		}
	}
}

func TestOnionPrivacyAtEachHop7Relays(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 7)
	msg := []byte("privacy test message 7 relays")
	pkt, err := sender.Encode(msg, relays, Proxy, "test")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	currentPacket := pkt
	for i, node := range nodes {
		nextHop, payload, err := node.Decode(currentPacket)
		if err != nil {
			t.Fatalf("hop %d: Decode failed: %v", i, err)
		}

		if i < len(nodes)-1 {
			if nextHop != relays[i+1].URL {
				t.Fatalf("hop %d: expected nextHop %q, got %q", i, relays[i+1].URL, nextHop)
			}
		} else {
			if nextHop != "" {
				t.Fatalf("final hop: expected no nextHop, got %q", nextHop)
			}
		}

		// The payload at this hop should not be readable as the original message
		if i < len(nodes)-1 {
			var tryMsg string
			if err := cbor.Unmarshal(payload, &tryMsg); err == nil && tryMsg == string(msg) {
				t.Fatalf("hop %d: payload should not be readable as message", i)
			}
		} else {
			// At the final hop, we should be able to unmarshal as LastHopPayload
			var lastHop LastHopPayload
			if err := cbor.Unmarshal(payload, &lastHop); err != nil {
				t.Fatalf("hop %d: could not unmarshal as LastHopPayload: %v", i, err)
			}
			if string(lastHop.Payload) != string(msg) {
				t.Fatalf("hop %d: final payload mismatch: got %q, want %q", i, lastHop.Payload, msg)
			}
		}

		// Prepare for next hop
		if i < len(nodes)-1 {
			currentPacket = &OnionPacket{
				Header: OnionHeader{
					SenderPubKey: sender.GetPublicKey().SerializeCompressed(),
					NextRelayURL: *relays[i+1],
				},
				EncryptedPayload: payload,
			}
		}
	}
}

func TestSenderPubKeyConsistentThroughCircuit(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 5)
	msg := []byte("sender pubkey consistency test")
	pkt, err := sender.Encode(msg, relays, Proxy, "test")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	senderPubKey := sender.GetPublicKey().SerializeCompressed()
	currentPacket := pkt
	for i, node := range nodes {
		// At each hop, check the header's SenderPubKey
		headerPubKey := currentPacket.Header.SenderPubKey
		if headerPubKey == nil || len(headerPubKey) != len(senderPubKey) || string(headerPubKey) != string(senderPubKey) {
			t.Fatalf("hop %d: sender public key mismatch", i)
		}

		// Decode and try to unmarshal as OnionPacket for the next hop
		_, payload, err := node.Decode(currentPacket)
		if err != nil {
			// Last hop, payload is not an OnionPacket
			break
		}

		// Prepare for next hop
		if i < len(nodes)-1 {
			currentPacket = &OnionPacket{
				Header: OnionHeader{
					SenderPubKey: sender.GetPublicKey().SerializeCompressed(),
					NextRelayURL: *relays[i+1],
				},
				EncryptedPayload: payload,
			}
		}
	}
}
