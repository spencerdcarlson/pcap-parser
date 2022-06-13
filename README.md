# Pcap

Elixir PCAP Next Generation (pcapng) Capture File Parser. [IETF Draft](https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html)

## Installation

```elixir
def deps do
  [
    {:pcap, github: "spencerdcarlson/pcap-parser"}
  ]
end
```

## Usage
There are two options for parsing a PCAP file:
1. `Pcap.Server` - Stateful file parser.
2. `Pcap.parse/1` - Parse the entire file all at once.

`Pcap.Server` only reads one block at a time, so memory usage should be relatively constant.

### Stateful Example
```elixir
# Create a stateful file parser
Pcap.Server.start_link([file: "./priv/one-packet.pcapng"])
# Get next Block
Pcap.Server.next()
# Get next Block
Pcap.Server.next()
# ...
# Shutdown stateful file parser
Pcap.Server |> Process.whereis() |> Process.exit(:normal)
```

### Stateless Example
```elixir
# Parse the entire file and get all back all blocks
Pcap.parse("./priv/one-packet.pcapng")
```