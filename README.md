# shallot

`shallot` is a Nostr relay implementation in Go that supports onion-routed messages. It is built using the `khatru` library.

## Project Goals

- Create a functional Nostr relay.
- Implement onion routing for Nostr messages to enhance user privacy.
- Serve as a reference implementation for onion-routed Nostr communication.

## Features

- **Onion Routing Support**: Implements Sphinx onion routing for Nostr events (kind 720)
- **NIP-66 Compliance**: Automatically generates and publishes relay discovery events for network discovery
- **Single Connection Policy**: Maintains only one WebSocket connection per relay for efficiency
- **Packet Validation**: Validates onion packet sizes to ensure protocol compliance
- **Privacy Focused**: All onion packets are constant size (12KB) to prevent traffic analysis

## Building

```bash
go build -o shallot-relay github.com/lescuer97/shallot/cmd/shallot
```

## Running

```bash
./shallot-relay --port 10023 --name my-shallot-relay
```

Optional flags:
- `--port`: Port to listen on (default: 10023)
- `--name`: Name of the relay (default: "shallot")

When the relay starts, it will:
1. Generate and display a NIP-66 relay discovery event (kind 30166) using the localhost address and specified port
2. Automatically publish this event to a local relay at `ws://localhost:4869`
3. Start serving requests on the specified port

This event indicates that the relay supports onion routing (kind 720 events) and makes it discoverable on the Nostr network.

## Onion Routing

The relay handles Nostr events of kind 720 as onion routing messages. These messages are:
1. Decrypted using the Sphinx protocol
2. Validated for correct packet size (12KB)
3. Forwarded to the next relay in the circuit if applicable
4. Delivered to the final destination if this relay is the terminus

## Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./circuit
go test ./sphinx
```
