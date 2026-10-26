
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"passive-asset-discovery/analysis"
	"passive-asset-discovery/capture"
	"passive-asset-discovery/fingerprints"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./cmd <path-to-pcap-file>")
		os.Exit(1)
	}

	path := os.Args[1]

	src, err := capture.NewPCAPSource(path)
	if err != nil {
		fmt.Println("Error opening pcap:", err)
		os.Exit(1)
	}
	defer src.Close()

	devices := make(map[string]analysis.DeviceInfo)
	firstSeen := make(map[string]time.Time)
	lastSeen := make(map[string]time.Time)
	hostnames := make(map[string]string)
	evidenceMap := make(map[string][]string)
	mdnsGuess := make(map[string]string)
	httpGuess := make(map[string]string)

	// Process packets from the recorded PCAP file.
	for {
		packet, err := src.Next()
		if err != nil {
			break
		}

		info, ok := analysis.ExtractDevice(packet)
		if !ok || info.MAC == "" {
			continue
		}

		ts := packet.Metadata().Timestamp

		existing, seen := devices[info.MAC]
		if !seen {
			devices[info.MAC] = info
			firstSeen[info.MAC] = ts
		} else if existing.IP == "" && info.IP != "" {
			devices[info.MAC] = info
		}

		lastSeen[info.MAC] = ts

		// DHCP hostname clue.
		if hostname, ev, ok := analysis.DHCPHostname(packet); ok {
			hostnames[info.MAC] = hostname
			evidenceMap[info.MAC] = append(
				evidenceMap[info.MAC],
				ev,
			)
		}

		// mDNS fingerprinting clue.
		if guess, ev, ok := analysis.MDNSClue(packet); ok {
			evidenceMap[info.MAC] = append(
				evidenceMap[info.MAC],
				ev,
			)

			if guess != "unknown" {
				mdnsGuess[info.MAC] = guess
			}
		}

		// HTTP banner fingerprinting clue.
		if banner, ev, ok := analysis.HTTPBannerClue(packet); ok {
			evidenceMap[info.MAC] = append(
				evidenceMap[info.MAC],
				ev,
			)

			guess := fingerprints.GuessTypeFromBanner(banner)
			if guess != "unknown" {
				httpGuess[info.MAC] = guess
			}
		}
	}

	// Build the asset list.
	var assets []analysis.Asset

	for mac, dev := range devices {
		vendor := fingerprints.LookupVendor(mac)

		// Copy evidence before appending vendor evidence.
		evidence := append([]string(nil), evidenceMap[mac]...)

		if vendor != "" {
			evidence = append(evidence, "mac oui")
		}

		deviceType := "unknown"
		confidence := "low"

		// Initial guess based on MAC vendor.
		if vendor != "" {
			guessed := fingerprints.GuessTypeFromVendor(vendor)
			if guessed != "unknown" {
				deviceType = guessed
			}
		}

		// mDNS can override the vendor-based guess.
		if mg, ok := mdnsGuess[mac]; ok {
			deviceType = mg
			confidence = "medium"

			// Vendor information and mDNS evidence are both present.
			if vendor != "" {
				confidence = "high"
			}
		}

		// HTTP banner-based device-type inference.
		if hg, ok := httpGuess[mac]; ok {
			if deviceType == "unknown" {
				deviceType = hg
				confidence = "medium"
			} else if hg == deviceType {
				confidence = "high"
			}
		}

		// DHCP hostname provides additional evidence.
		if hostnames[mac] != "" && confidence == "low" {
			confidence = "medium"
		}

		asset := analysis.Asset{
			IP:         dev.IP,
			MAC:        mac,
			Vendor:     vendor,
			DeviceType: deviceType,
			Confidence: confidence,
			Hostname:   hostnames[mac],
			Evidence:   evidence,
			FirstSeen:  firstSeen[mac].UTC().Format(time.RFC3339),
			LastSeen:   lastSeen[mac].UTC().Format(time.RFC3339),
		}

		assets = append(assets, asset)
	}

	// Convert assets to formatted JSON.
	output, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		fmt.Println("Error building JSON:", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
