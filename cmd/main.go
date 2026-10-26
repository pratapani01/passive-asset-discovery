package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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

		if hostname, ev, ok := analysis.DHCPHostname(packet); ok {
			hostnames[info.MAC] = hostname
			evidenceMap[info.MAC] = append(evidenceMap[info.MAC], ev)
		}

		if guess, ev, ok := analysis.MDNSClue(packet); ok {
			evidenceMap[info.MAC] = append(evidenceMap[info.MAC], ev)
			if guess != "unknown" {
				mdnsGuess[info.MAC] = guess
			}
		}

		if banner, ev, ok := analysis.HTTPBannerClue(packet); ok {
			evidenceMap[info.MAC] = append(evidenceMap[info.MAC], ev)
			guess := fingerprints.GuessTypeFromBanner(banner)
			if guess != "unknown" {
				httpGuess[info.MAC] = guess
			}
		}
	}

	var assets []analysis.Asset
	for mac, dev := range devices {
		vendor := fingerprints.LookupVendor(mac)

		evidence := evidenceMap[mac]
		if evidence == nil {
			evidence = []string{}
		}
		if vendor != "" {
			evidence = append(evidence, "mac oui")
		}

		deviceType := "unknown"
		confidence := "low"

		if vendor != "" {
			guessed := fingerprints.GuessTypeFromVendor(vendor)
			if guessed != "unknown" {
				deviceType = guessed
				confidence = "low"
			}
		}

		if mg, ok := mdnsGuess[mac]; ok {
			if deviceType == "unknown" {
				deviceType = mg
				confidence = "medium"
			} else if mg == deviceType {
				confidence = "high"
			}
		}

		if hg, ok := httpGuess[mac]; ok {
			if deviceType == "unknown" {
				deviceType = hg
				confidence = "medium"
			} else if hg == deviceType {
				confidence = "high"
			}
		}

		if hostnames[mac] != "" && confidence == "low" {
			confidence = "medium"
		}

		assets = append(assets, analysis.Asset{
			IP:         dev.IP,
			MAC:        mac,
			Vendor:     vendor,
			DeviceType: deviceType,
			Confidence: confidence,
			Hostname:   hostnames[mac],
			Evidence:   evidence,
			FirstSeen:  firstSeen[mac].UTC().Format(time.RFC3339),
			LastSeen:   lastSeen[mac].UTC().Format(time.RFC3339),
		})
	}

	output, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		fmt.Println("Error building JSON:", err)
		os.Exit(1)
	}

	// JSON file me save karo (viewer isko load karega)
	err = os.WriteFile("web/assets.json", output, 0644)
	if err != nil {
		fmt.Println("Error saving JSON:", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
	fmt.Println("\nSaved to web/assets.json")
	fmt.Println("Starting viewer at http://localhost:8080")

	// Simple web server: web folder serve karo
	http.Handle("/", http.FileServer(http.Dir("web")))
	http.ListenAndServe(":8080", nil)
}