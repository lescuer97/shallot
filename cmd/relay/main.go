package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/fiatjaf/eventstore/sqlite3"
	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/lescuer97/shallot/circuit"
	"github.com/nbd-wtf/go-nostr"
)

func main() {
	port := flag.Int("port", 3334, "port to start the websocket on")
	flag.Parse()
	relay := khatru.NewRelay()

	db := sqlite3.SQLite3Backend{DatabaseURL: "./db"}
	if err := db.Init(); err != nil {
		panic(err)
	}

	circuitHandler, err := circuit.NewCircuitHandler()
	if err != nil {
		log.Panic("could not start the circuit handler. %w", err)
	}

	policies.ApplySaneDefaults(relay)

	relay.StoreEvent = append(relay.StoreEvent,
		func(ctx context.Context, event *nostr.Event) error {
			// TODO: check if the event is an onion event and if it send it to the circuit manager. if not do a normal
			// operation.
			if event.Kind == circuit.OnionMsgKind {
				isFinal, cellCommand, relayCommand, err := circuitHandler.ProcessNostrEvent(event)
				if err != nil {
					log.Printf("Something went wrong. %+v", err)
				}

				if isFinal && cellCommand == nil {
					log.Panicf("if the last hop is final there should have always been some end command")
				}

				if isFinal && relayCommand != nil {

				}

			} else {
				db.SaveEvent(ctx, event)
			}

			return nil
		},
	)

	relay.StoreEvent = append(relay.StoreEvent, db.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, db.QueryEvents)
	relay.CountEvents = append(relay.CountEvents, db.CountEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, db.DeleteEvent)
	relay.ReplaceEvent = append(relay.ReplaceEvent, db.ReplaceEvent)

	portStr := fmt.Sprintf(":%v", *port)
	fmt.Printf("running on %v", portStr)
	http.ListenAndServe(portStr, relay)
}
