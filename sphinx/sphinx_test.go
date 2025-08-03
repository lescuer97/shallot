package sphinx

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestEncryptionSphinx(t *testing.T) {

	sphinx, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make clientSphinx. %+v", err)
	}
	sphinx2, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx2. %+v", err)
	}
	payload := "hello world"

	encryptedPayload, err := sphinx.EncryptPayload([]byte(payload), sphinx2.PublicKey)
	if err != nil {
		t.Fatalf("could not encrypt payload. %+v", err)
	}

	encryptedPayload, err = sphinx2.DecryptPayload(encryptedPayload, sphinx.PublicKey)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 2. %+v", err)
	}

	if string(encryptedPayload) != payload {
		t.Errorf("Could not decrypt the payload correctly. Should have been %v. IS: %v", payload, encryptedPayload)
	}

}
func TestEncryptionOf3Sphinx(t *testing.T) {

	clientSphinx, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make clientSphinx. %+v", err)
	}

	sphinx1, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx1. %+v", err)
	}

	sphinx2, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx2. %+v", err)
	}

	sphinx3, err := NewSphinx()
	if err != nil {
		t.Fatalf("could not make sphinx3. %+v", err)
	}

	payload := "hello world"

	encryptedPayload, err := clientSphinx.EncryptPayloadWithList([]byte(payload), []*btcec.PublicKey{sphinx1.PublicKey, sphinx2.PublicKey, sphinx3.PublicKey})
	if err != nil {
		t.Fatalf("could not encrypt payload. %+v", err)
	}

	encryptedPayload, err = sphinx3.DecryptPayload(encryptedPayload, clientSphinx.PublicKey)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 3. %+v", err)
	}

	if string(encryptedPayload) == payload {
		t.Errorf("Encrypted Payload should not be readable here. sphinx3 %v. IS: %v", payload, encryptedPayload)
	}

	encryptedPayload, err = sphinx2.DecryptPayload(encryptedPayload, clientSphinx.PublicKey)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 2. %+v", err)
	}
	if string(encryptedPayload) == payload {
		t.Errorf("Encrypted Payload should not be readable here. sphinx2 %v. IS: %v", payload, encryptedPayload)
	}
	encryptedPayload, err = sphinx1.DecryptPayload(encryptedPayload, clientSphinx.PublicKey)
	if err != nil {
		t.Fatalf("could not decrypt payload with sphinx 2. %+v", err)
	}

	if string(encryptedPayload) != payload {
		t.Errorf("Could not decrypt the payload correctly. Should have been %v. IS: %v", payload, encryptedPayload)
	}

}
