# Passive Asset Discovery

A tool that reads a network traffic capture (PCAP) file and identifies the
devices on the network — passively, without ever touching them.

## What it does

- Reads packets from a `.pcap` file
- Extracts each device's IP and MAC address
- Looks up the device's maker (vendor) from its MAC address
- Guesses the device type (camera, printer, router, etc.) using:
  - Vendor name
  - DHCP hostname
  - mDNS service announcements
  - HTTP Server banners
- Outputs a JSON list of devices (`web/assets.json`)
- Serves a simple web viewer to browse the results

## How to run

### From source

go run ./cmd/main.go <path-to-pcap-file>


### Using a pre-built binary

./passive-scan-linux <path-to-pcap-file> # Linux
./passive-scan-windows.exe <path-to-pcap-file> # Windows
./passive-scan-mac <path-to-pcap-file> # Mac


After running, open **http://localhost:8080/viewer.html** in a browser to
see the results in a table.

## How to build

CGO_ENABLED=0 GOOS=linux go build -o build/passive-scan-linux ./cmd
CGO_ENABLED=0 GOOS=windows go build -o build/passive-scan-windows.exe ./cmd
CGO_ENABLED=0 GOOS=darwin go build -o build/passive-scan-mac ./cmd


## Project structure

- `/cmd` — main program
- `/capture` — PacketSource interface + PCAP reader
- `/analysis` — device identification logic (IP/MAC extraction, DHCP, mDNS, HTTP clues)
- `/fingerprints` — MAC-to-vendor lookup and device-type guessing rules
- `/web` — simple viewer webpage
- `/testdata` — sample PCAP files for testing

## Output format

Each device in the JSON output has: `ip`, `mac`, `vendor`, `device_type`,
`confidence` (high/medium/low), `hostname`, `evidence` (list of clues used),
`first_seen`, `last_seen`.

## Notes

- Confidence is "high" when two or more independent clues agree on the
  device type, "medium" when one clue is found, and "low" when only the
  vendor name is available.
- An "unknown" device type is preferred over a confident wrong guess.

