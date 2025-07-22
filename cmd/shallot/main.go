package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/lescuer97/shallot/sphinx"
	"github.com/nbd-wtf/go-nostr"
)

func main() {
	relay := khatru.NewRelay()

	sphinx, err := sphinx.NewSphinx()
	if err != nil {
		log.Panicf("could not generate sphinx keys")
	}

	relay.Info.Name = "shallot"
	relay.Info.Description = "This is an onion capable relay"
	relay.Info.PubKey = hex.EncodeToString(sphinx.GetPublicKey().SerializeCompressed())
	relay.Info.Contact = "_"
	policies.ApplySaneDefaults(relay)

	store := make(map[string]*nostr.Event, 120)
	relay.StoreEvent = append(relay.StoreEvent,
		func(ctx context.Context, event *nostr.Event) error {
			log.Printf("nostEvent. %+v", event)
			store[event.ID] = event
			return nil
		},
	)
	relay.QueryEvents = append(relay.QueryEvents,
		func(ctx context.Context, filter nostr.Filter) (chan *nostr.Event, error) {
			ch := make(chan *nostr.Event)
			go func() {
				for _, evt := range store {
					if filter.Matches(evt) {
						ch <- evt
					}
				}
				close(ch)
			}()
			return ch, nil
		},
	)

	// TODO: Implement onion message handling logic here.
	// This will involve:
	// 1. Identifying onion-encrypted messages.
	// 2. Decrypting the outer layer of the onion.
	// 3. Relaying the message to the next peer.

	// mux := relay.Router()
	// // set up other http handlers
	// mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	w.Header().Set("content-type", "text/html")
	// 	fmt.Fprintf(w, `<b>welcome</b> to my relay!`)
	// })

	// start the server
	fmt.Println("running on :10023")
	err = http.ListenAndServe(":10023", relay)
	if err != nil {
		log.Panicf("could not listen to server. %w", err)

	}

}
