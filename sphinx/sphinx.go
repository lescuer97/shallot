package sphinx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Sphinx struct holds the necessary components for the Sphinx encryption.
type Sphinx struct {
	privateKey *secp256k1.PrivateKey
	publicKey  *secp256k1.PublicKey
}

// NewSphinx creates a new Sphinx instance.
func NewSphinx() (*Sphinx, error) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.PubKey()

	return &Sphinx{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// Encode takes a message and a list of public keys and creates an onion-encrypted message.
func (s *Sphinx) Encode(message []byte, publicKeys []*secp256k1.PublicKey) ([]byte, error) {
	onion := message
	for i := len(publicKeys) - 1; i >= 0; i-- {
		sharedSecret, err := s.GenerateSharedSecret(publicKeys[i])
		if err != nil {
			return nil, err
		}

		encrypted, err := encrypt(onion, sharedSecret)
		if err != nil {
			return nil, err
		}

		// Prepend the sender's public key (unencrypted) so receiver can derive shared secret
		senderPubKeyBytes := s.publicKey.SerializeCompressed()
		onion = append(senderPubKeyBytes, encrypted...)
	}
	return onion, nil
}

// Decode takes an onion-encrypted message and attempts to decrypt one layer.
func (s *Sphinx) Decode(message []byte) ([]byte, *secp256k1.PublicKey, error) {
	// Extract sender's public key from the first 33 bytes
	if len(message) < 33 {
		return nil, nil, fmt.Errorf("message too short to contain public key")
	}

	senderKeyBytes := message[:33]
	encryptedPayload := message[33:]

	// Parse the sender's public key
	senderPubKey, err := secp256k1.ParsePubKey(senderKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse sender public key: %v", err)
	}

	// Generate shared secret using receiver's private key and sender's public key
	sharedSecret, err := s.GenerateSharedSecret(senderPubKey)
	if err != nil {
		return nil, nil, err
	}

	// Decrypt the payload
	decrypted, err := decrypt(encryptedPayload, sharedSecret)
	if err != nil {
		return nil, nil, err
	}

	return decrypted, senderPubKey, nil
}

// GenerateSharedSecret generates a shared secret using ECDH.
func (s *Sphinx) GenerateSharedSecret(publicKey *secp256k1.PublicKey) ([]byte, error) {
	return secp256k1.GenerateSharedSecret(s.privateKey, publicKey), nil
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:32])
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, io.ErrUnexpectedEOF
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// read io.Reader for cryptographic purposes.
var cRand io.Reader = rand.Reader
