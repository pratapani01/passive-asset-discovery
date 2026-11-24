# Passive Asset Discovery

Identifies the devices on a network by listening to its traffic. The tool never
sends a packet, never scans and never connects to a device. It reads either a
recorded capture file (`.pcap` / `.pcapng`) or live traffic from a network
interface, and builds an inventory of what it saw.

For every device it reports the IP address, the MAC address, the vendor, a guess
of the device type (router, phone, printer, camera, ...), how confident that
guess is, and the evidence behind it. Results are shown as JSON and in a small
web page that refreshes by itself.

## What it can do today

- Read recorded captures in pcap and pcapng format.
- Listen live on a network interface (through Wireshark's `tshark`, so the tool
  itself stays pure Go and builds without CGO).
- List every device seen, with first-seen and last-seen times. A device that
  joins while the tool is running appears within a few seconds.
- Look up the vendor from the MAC address using the full IEEE OUI list, which is
  embedded in the binary (about 35,000 entries).
- Recognise phones that use a random (private) MAC address, which have no vendor.
- Guess the device type from independent clues: vendor name, DHCP hostname,
  mDNS hostname and service announcements, HTTP `Server` banners, SSDP/UPnP
  announcements.
- Rate each guess `low`, `medium` or `high` and list the evidence used.
- Find the default gateway (the MAC that forwards traffic from public IP
  addresses) and the subnet.
- Report TCP ports as open when a device is seen answering a connection
  (SYN-ACK). This is inferred from traffic only; nothing is probed.
- Show everything in a web viewer, and print the same data as JSON.
- Produce the same output every time for the same input (devices are sorted).

## Requirements

- To build: Go 1.21 or newer, and internet access the first time to download
  the `gopacket` module.
- To read a capture file: nothing else.
- To capture live: Wireshark (it provides `tshark`). On Windows this also
  installs Npcap. Capturing needs permission: run the terminal as
  Administrator on Windows, use `sudo` on Linux or macOS, or allow non-root
  capture for Wireshark on your system.

## Quick start

Read a capture file:

```
go run ./cmd testdata/NTP_sync.pcap
```

The JSON is printed and the viewer starts at http://127.0.0.1:8080/viewer.html.
Press Ctrl+C to stop. Add `-no-web` to print the JSON and exit.

Capture live on Wi-Fi (Windows):

```
go run ./cmd live Wi-Fi
```

Other systems need the interface name. List the available names with
`tshark -D`, then for example:

```
go run ./cmd live wlan0
go run ./cmd live en0
```

On macOS the default interface is `en0`, so `go run ./cmd live` is enough. On
Linux the interface name is always required.

## Command line

```
passive-scan [flags] <capture.pcap | capture.pcapng>
passive-scan [flags] live [interface]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8080` | Address the web viewer listens on. The default is reachable from this computer only. Use `:8080` to share it on the local network. |
| `-tshark` | found automatically | Path to `tshark`, for live mode. It is looked up on `PATH` and in the default Wireshark install folders. |
| `-no-web` | off | In file mode, print the JSON and exit. |

## Web viewer and endpoints

The viewer is embedded in the binary, so no other file has to be shipped with
it.

| URL | Content |
| --- | --- |
| `/viewer.html` | The device table. It refreshes every 3 seconds. |
| `/assets.json` | The device list as JSON. |
| `/network.json` | Subnet, gateway and device count. |

## Output format

Each device in `/assets.json` (and in the JSON printed in file mode):

```json
{
  "ip": "192.168.29.73",
  "mac": "66:00:ab:02:df:f7",
  "vendor": "",
  "device_type": "phone",
  "confidence": "medium",
  "hostname": "motorola-edge-50-fusion",
  "evidence": ["dhcp hostname", "private (random) mac"],
  "first_seen": "2026-11-22T04:08:37Z",
  "last_seen": "2026-11-22T04:08:37Z"
}
```

| Field | Meaning |
| --- | --- |
| `ip` | The first private IPv4 address seen for this MAC. Empty if none was seen yet. |
| `mac` | Hardware address. |
| `vendor` | Manufacturer from the OUI list. Empty for random MACs and unknown prefixes. |
| `device_type` | `router`, `phone`, `computer`, `printer`, `ip_camera`, `tv_or_speaker`, `iot_device` or `unknown`. |
| `confidence` | `low`, `medium` or `high`. |
| `hostname` | From DHCP, or from mDNS when DHCP gave none. Left out when unknown. |
| `evidence` | What the guess is based on (see below). |
| `first_seen`, `last_seen` | UTC timestamps taken from the packets. |

`/network.json`:

```json
{
  "subnet": "192.168.29.0/24",
  "subnet_source": "assumed /24",
  "gateway": "192.168.29.1",
  "gateway_mac": "04:70:56:f8:63:87",
  "device_count": 4
}
```

`subnet_source` is `dhcp` when a DHCP reply with the subnet mask was seen, and
`assumed /24` otherwise.

## How a device is identified

Evidence strings and where they come from:

| Evidence | Source |
| --- | --- |
| `mac oui` | The vendor was found in the OUI list. |
| `dhcp hostname` | Hostname sent in a DHCP request. |
| `mdns hostname` | Hostname announced in an mDNS response. |
| `mdns _ipp._tcp` (and similar) | mDNS service announcement, for example printer, camera or Chromecast services. |
| `http banner: <text>` | `Server` header of an HTTP response sent by the device. |
| `ssdp <token>` / `ssdp server: <text>` | SSDP/UPnP announcement. |
| `open port 80/tcp` | The device was seen accepting a TCP connection on that port. |
| `private (random) mac` | The MAC is locally administered, as used by phones for privacy. |
| `default gateway` | The device forwards traffic from public IP addresses. |

Confidence rules: a device starts as `unknown` / `low`. A type taken from the
vendor name alone stays `low`. The first other clue that names a type gives
`medium`. A second clue that names the same type gives `high`. If clues
disagree, the earlier type is kept. A device with no usable clue stays
`unknown`; an honest unknown is preferred over a confident wrong answer.

## Build

```
go build -o passive-scan ./cmd
```

Single-file binaries for the three platforms, without CGO:

```
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o build/passive-scan-linux ./cmd
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o build/passive-scan-windows.exe ./cmd
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o build/passive-scan-mac ./cmd
```

On Windows PowerShell set the variables first, for example:

```
$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="amd64"
go build -o build/passive-scan-linux ./cmd
```

and reset them afterwards with `Remove-Item Env:GOOS, Env:GOARCH`. The `build/`
folder is not tracked by git.

## Tests

```
gofmt -l .
go vet ./...
go test ./...
```

The tests cover the vendor lookup, every fingerprint rule (vendor, banner,
hostname, mDNS, SSDP), the confidence logic, gateway and subnet detection, and
the device lists produced from the two sample captures in `testdata/`. The
sample captures are public Wireshark sample files. Captures of a real home or
office network must not be committed; `.gitignore` already excludes
`testdata/home.pcap`, `testdata/home.pcapng` and `testdata/*.local.*`.

## Project layout

| Path | Purpose |
| --- | --- |
| `cmd/` | Command line, device tracker, web server. |
| `capture/` | `PacketSource` interface, pcap/pcapng reader, live reader (`tshark`). |
| `analysis/` | Pulls facts out of a packet: MAC, IP, ARP, DHCP, mDNS, HTTP, SSDP, ports. |
| `fingerprints/` | OUI vendor lookup (`oui.txt`) and the device type rules. |
| `web/` | The viewer page, embedded into the binary. |
| `testdata/` | Sample captures used by the tests. |

The rest of the program only talks to the `PacketSource` interface, so a new
source of packets can be added without changing the analysis code.

## Limitations

- On a normal switched or Wi-Fi network one computer sees only its own traffic
  plus broadcast and multicast traffic (ARP, DHCP, mDNS, SSDP). A device that
  stays quiet may not show up until it announces itself. Seeing everything
  needs a mirror (SPAN) port, the router, or a Wi-Fi adapter in monitor mode.
- Open ports appear only when the connection handshake passed the capture point.
- Phones with random MACs have no vendor. Their type depends on hostname clues.
- Device types are heuristics based on keyword rules. Check the `evidence` and
  `confidence` before relying on a result.
- IPv4 only. IPv6 addresses and neighbour discovery are not read.
- The subnet is assumed to be a /24 unless a DHCP reply with the mask was seen.
- The default gateway is the sender of traffic from public IP addresses, so it is
  only known once such traffic has been seen.
- The inventory lives in memory and is lost when the tool stops.
- The viewer has no login. Keep the default local address unless the network is
  trusted.
- Live mode has been tried on Windows with Wi-Fi. Linux and macOS use the same
  code path but are not tested yet.

## Possible next steps

- Read IPv6 and neighbour discovery traffic.
- Use the DHCP parameter request list (option 55) as a fingerprint.
- Use TLS server names and more mDNS records to improve type guesses.
- Save the inventory to disk and keep a history per device.
- Raise an alert when a new device joins.
- Export to CSV.
- Add labelled sample captures per device type to check accuracy.
- Run on the router or a mirror port for full visibility.
