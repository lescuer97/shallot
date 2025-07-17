package sphinx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/url"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	NumMaxHops = 10
)

type Sphinx struct {
	privateKey *secp256k1.PrivateKey
	publicKey  *secp256k1.PublicKey
}

type Relay struct {
	PublicKey *secp256k1.PublicKey
	URL       string
}

type OnionPacket struct {
	SenderPubKey     []byte
	EncryptedPayload []byte
}

func NewSphinx() (*Sphinx, error) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return &Sphinx{
		privateKey: privateKey,
		publicKey:  privateKey.PubKey(),
	}, nil
}

func NewRelay(pubKey *secp256k1.PublicKey, rawURL string) (*Relay, error) {
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return nil, fmt.Errorf("invalid relay URL: %w", err)
	}
	return &Relay{PublicKey: pubKey, URL: rawURL}, nil
}

func (s *Sphinx) GetPublicKey() *secp256k1.PublicKey {
	return s.publicKey
}

func (s *Sphinx) Encode(message []byte, relays []*Relay) (*OnionPacket, error) {
	if len(relays) == 0 {
		return nil, fmt.Errorf("at least one relay is required")
	}

	if len(relays) > NumMaxHops {
		return nil, fmt.Errorf("too many hops: %d > %d", len(relays), NumMaxHops)
	}

	if len(message) == 0 {
		return nil, fmt.Errorf("cannot encode zero-length message")
	}

	encryptedPayload, err := s.encodePayload(message, relays)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	return &OnionPacket{
		SenderPubKey:     s.publicKey.SerializeCompressed(),
		EncryptedPayload: encryptedPayload,
	}, nil
}

func (s *Sphinx) encodePayload(payload []byte, relays []*Relay) ([]byte, error) {
	log.Printf("Starting encoding for payload of size %d", len(payload))
	
	currentPayload := payload
	var err error

	// Build the onion layers from innermost to outermost
	for i := len(relays) - 1; i >= 0; i-- {
		var header []byte
		
		if i == len(relays)-1 {
			// Final hop - no next hop URL, just empty header
			header = make([]byte, 2)
			binary.BigEndian.PutUint16(header, 0) // 0 length indicates final hop
		} else {
			// Intermediate hop - include next hop URL
			nextHopURL := []byte(relays[i+1].URL)
			header = make([]byte, 2+len(nextHopURL))
			binary.BigEndian.PutUint16(header, uint16(len(nextHopURL)))
			copy(header[2:], nextHopURL)
		}

		combined := append(header, currentPayload...)
		currentPayload, err = s.encryptLayer(combined, relays[i].PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt layer for hop %d: %w", i, err)
		}
		log.Printf("Encoded layer for hop %d, new payload size: %d", i, len(currentPayload))
	}

	return currentPayload, nil
}

func (s *Sphinx) encryptLayer(payload []byte, recipientPubKey *secp256k1.PublicKey) ([]byte, error) {
	sharedSecret, err := s.generateSharedSecret(recipientPubKey)
	if err != nil {
		return nil, err
	}

	encrypted, err := encrypt(payload, sharedSecret)
	if err != nil {
		return nil, err
	}

	return append(s.publicKey.SerializeCompressed(), encrypted...), nil
}

func (s *Sphinx) Decode(packet *OnionPacket) (nextHopURL string, payload []byte, err error) {
	log.Printf("Starting decoding for packet of size %d", len(packet.EncryptedPayload))
	decrypted, senderPubKey, err := s.decryptLayer(packet.EncryptedPayload)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decrypt layer: %w", err)
	}

	log.Printf("Successfully decrypted layer from sender %x", senderPubKey.SerializeCompressed())

	// Parse the routing header
	if len(decrypted) < 2 {
		return "", nil, fmt.Errorf("payload is too short for header")
	}
	
	urlLen := int(binary.BigEndian.Uint16(decrypted[:2]))
	
	// If urlLen is 0, this is the final hop
	if urlLen == 0 {
		// Final hop - return the payload
		payload = decrypted[2:]
		if len(payload) == 0 {
			return "", nil, fmt.Errorf("payload is empty")
		}
		log.Printf("Final hop, payload size: %d", len(payload))
		return "", payload, nil
	}
	
	// Intermediate hop - extract next hop URL
	if len(decrypted) < 2+urlLen {
		return "", nil, fmt.Errorf("payload is too short for URL")
	}

	nextHopURL = string(decrypted[2 : 2+urlLen])
	payload = decrypted[2+urlLen:]
	log.Printf("Forwarding to next hop: %s, payload size: %d", nextHopURL, len(payload))
	return nextHopURL, payload, nil
}

func (s *Sphinx) decryptLayer(payload []byte) ([]byte, *secp256k1.PublicKey, error) {
	if len(payload) < 33 {
		return nil, nil, fmt.Errorf("payload is too short")
	}
	senderPubKeyBytes := payload[:33]
	log.Printf("Attempting to parse sender public key: %x", senderPubKeyBytes)
	senderPubKey, err := secp256k1.ParsePubKey(senderPubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse sender public key: %w", err)
	}
	sharedSecret, err := s.generateSharedSecret(senderPubKey)
	if err != nil {
		return nil, nil, err
	}
	decrypted, err := decrypt(payload[33:], sharedSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return decrypted, senderPubKey, nil
}

func (s *Sphinx) generateSharedSecret(recipientPubKey *secp256k1.PublicKey) ([]byte, error) {
	sharedSecret := secp256k1.GenerateSharedSecret(s.privateKey, recipientPubKey)
	key := sha256.Sum256(sharedSecret)
	return key[:], nil
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
