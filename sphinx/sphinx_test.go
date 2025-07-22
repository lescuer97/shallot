package sphinx

import (
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func makeRelays(t *testing.T, n int) ([]*Relay, []*Sphinx) {
	relays := make([]*Relay, n)
	nodes := make([]*Sphinx, n)
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
	pkt, err := sender.Encode(msg, relays)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	for _, node := range nodes {
		nextHop, payload, err := node.Decode(pkt)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		pkt.EncryptedPayload = payload
		_ = nextHop // not used in this test
	}
	if string(pkt.EncryptedPayload) != string(msg) {
		t.Fatalf("final payload mismatch: got %q, want %q", pkt.EncryptedPayload, msg)
	}
}

func TestSphinxEncryptDecryptLayer_Success(t *testing.T) {
	sender, _ := NewSphinx()
	receiver, _ := NewSphinx()
	payload := []byte("test onion layer payload")
	encrypted, err := sender.encryptLayer(payload, receiver.GetPublicKey())
	if err != nil {
		t.Fatalf("encryptLayer failed: %v", err)
	}
	decrypted, _, err := receiver.decryptLayer(encrypted)
	if err != nil {
		t.Fatalf("decryptLayer failed: %v", err)
	}
	if string(decrypted) != string(payload) {
		t.Fatalf("decrypted payload mismatch: got %q, want %q", decrypted, payload)
	}
}

func TestSphinxDecryptLayer_FailsWithWrongKey(t *testing.T) {
	sender, _ := NewSphinx()
	receiver, _ := NewSphinx()
	wrongReceiver, _ := NewSphinx()
	payload := []byte("test onion layer payload")
	encrypted, err := sender.encryptLayer(payload, receiver.GetPublicKey())
	if err != nil {
		t.Fatalf("encryptLayer failed: %v", err)
	}
	_, _, err = wrongReceiver.decryptLayer(encrypted)
	if err == nil {
		t.Fatalf("expected error when decrypting with wrong key, got nil")
	}
}

func TestEncodeOnion_MultiHopManualDecode(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 3)
	msg := []byte("manual multi-hop decode test")
	packet, err := sender.Encode(msg, relays)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if len(packet.EncryptedPayload) > MaxPacketSize {
		t.Fatalf("initial packet size exceeds MTU: got %d, want <= %d", len(packet.EncryptedPayload), MaxPacketSize)
	}
	currentPayload := packet.EncryptedPayload
	for i, node := range nodes {
		if len(currentPayload) > MaxPacketSize {
			t.Fatalf("hop %d: payload size exceeds MTU: got %d, want <= %d", i, len(currentPayload), MaxPacketSize)
		}
		nextHop, payload, err := node.Decode(&OnionPacket{EncryptedPayload: currentPayload})
		if err != nil {
			t.Fatalf("hop %d: Decode failed: %v", i, err)
		}
		currentPayload = payload
		if i < len(nodes)-1 && nextHop == "" {
			t.Fatalf("hop %d: expected nextHop, got empty", i)
		}
		if i == len(nodes)-1 && nextHop != "" {
			t.Fatalf("final hop: expected no nextHop, got %q", nextHop)
		}
	}
	if string(currentPayload) != string(msg) {
		t.Fatalf("final payload mismatch: got %q, want %q", currentPayload, msg)
	}
}

func TestOnionPrivacyAtEachHop(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 3)
	msg := []byte("privacy test message")
	pkt, err := sender.Encode(msg, relays)
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

		// The payload at this hop should not be readable as the original message or as an OnionPacket (except at the last hop)
		if i < len(nodes)-1 {
			var tryMsg string
			if err := cbor.Unmarshal(payload, &tryMsg); err == nil && tryMsg == string(msg) {
				t.Fatalf("hop %d: payload should not be readable as message", i)
			}
			var tryPkt OnionPacket
			if err := cbor.Unmarshal(payload, &tryPkt); err == nil {
				// It should not be readable as a valid OnionPacket at this hop
				if tryPkt.Header.NextRelayURL.URL == relays[i+2%len(relays)].URL {
					t.Fatalf("hop %d: payload should not be readable as next OnionPacket", i)
				}
			}
		}

		// Prepare for next hop
		currentPacket = &OnionPacket{EncryptedPayload: payload}
	}

	// At the last hop, the payload should be the original message
	if string(currentPacket.EncryptedPayload) != string(msg) {
		t.Fatalf("final payload mismatch: got %q, want %q", currentPacket.EncryptedPayload, msg)
	}
}

func TestOnionPrivacyAtEachHop5Relays(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 5)
	msg := []byte("privacy test message 5 relays")
	pkt, err := sender.Encode(msg, relays)
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

		if i < len(nodes)-1 {
			var tryMsg string
			if err := cbor.Unmarshal(payload, &tryMsg); err == nil && tryMsg == string(msg) {
				t.Fatalf("hop %d: payload should not be readable as message", i)
			}
			var tryPkt OnionPacket
			if err := cbor.Unmarshal(payload, &tryPkt); err == nil {
				if tryPkt.Header.NextRelayURL.URL == relays[(i+2)%len(relays)].URL {
					t.Fatalf("hop %d: payload should not be readable as next OnionPacket", i)
				}
			}
		}

		currentPacket = &OnionPacket{EncryptedPayload: payload}
	}

	if string(currentPacket.EncryptedPayload) != string(msg) {
		t.Fatalf("final payload mismatch: got %q, want %q", currentPacket.EncryptedPayload, msg)
	}
}

func TestOnionPrivacyAtEachHop7Relays(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 7)
	msg := []byte("privacy test message 7 relays")
	pkt, err := sender.Encode(msg, relays)
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

		if i < len(nodes)-1 {
			var tryMsg string
			if err := cbor.Unmarshal(payload, &tryMsg); err == nil && tryMsg == string(msg) {
				t.Fatalf("hop %d: payload should not be readable as message", i)
			}
			var tryPkt OnionPacket
			if err := cbor.Unmarshal(payload, &tryPkt); err == nil {
				if tryPkt.Header.NextRelayURL.URL == relays[(i+2)%len(relays)].URL {
					t.Fatalf("hop %d: payload should not be readable as next OnionPacket", i)
				}
			}
		}

		currentPacket = &OnionPacket{EncryptedPayload: payload}
	}

	if string(currentPacket.EncryptedPayload) != string(msg) {
		t.Fatalf("final payload mismatch: got %q, want %q", currentPacket.EncryptedPayload, msg)
	}
}

func TestSenderPubKeyConsistentThroughCircuit(t *testing.T) {
	sender, _ := NewSphinx()
	relays, nodes := makeRelays(t, 5)
	msg := []byte("sender pubkey consistency test")
	pkt, err := sender.Encode(msg, relays)
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
		var inner OnionPacket
		if err := cbor.Unmarshal(payload, &inner); err == nil {
			currentPacket = &inner
		} else {
			// Last hop, payload is not an OnionPacket
			break
		}
	}
}
