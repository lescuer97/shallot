package sphinx

import (
	"fmt"
	"testing"
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
