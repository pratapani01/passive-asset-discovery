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
	}

	// Build the Asset list in the required JSON shape
	var assets []analysis.Asset
	for mac, dev := range devices {
		vendor := fingerprints.LookupVendor(mac)

		assets = append(assets, analysis.Asset{
			IP:         dev.IP,
			MAC:        mac,
			Vendor:     vendor,
			DeviceType: "unknown",   // Week 2 me isko sahi karenge
			Confidence: "low",       // abhi sirf vendor se guess hai
			Evidence:   []string{"mac oui"},
			FirstSeen:  firstSeen[mac].UTC().Format(time.RFC3339),
			LastSeen:   lastSeen[mac].UTC().Format(time.RFC3339),
		})
	}

	output, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		fmt.Println("Error building JSON:", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}