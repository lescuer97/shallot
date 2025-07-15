package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/fiatjaf/khatru"
)

func main() {
	relay := khatru.NewRelay()

	relay.Info.Name = "shallot"
	relay.Info.Description = "A Nostr relay with onion routing capabilities."
	relay.Info.PubKey = "_"
	relay.Info.Contact = "_"

	// TODO: Implement onion message handling logic here.
	// This will involve:
	// 1. Identifying onion-encrypted messages.
	// 2. Decrypting the outer layer of the onion.
	// 3. Relaying the message to the next peer.

	fmt.Println("shallot relay is running on :8080")
	if err := http.ListenAndServe(":8080", relay); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
