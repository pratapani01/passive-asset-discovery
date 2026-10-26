package main

import (
	"fmt"
	"os"

	"passive-asset-discovery/analysis"
	"passive-asset-discovery/capture"
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

	// MAC address ko key bana ke unique devices store karenge
	devices := make(map[string]analysis.DeviceInfo)

	packetCount := 0
	for {
		packet, err := src.Next()
		if err != nil {
			break
		}
		packetCount++

		info, ok := analysis.ExtractDevice(packet)
		if !ok || info.MAC == "" {
			continue // kuch useful nahi mila is packet me
		}

		// agar ye MAC pehle nahi dekha, ya is baar IP mili hai to update karo
		existing, seen := devices[info.MAC]
		if !seen {
			devices[info.MAC] = info
		} else if existing.IP == "" && info.IP != "" {
			devices[info.MAC] = info
		}
	}

	fmt.Println("Total packets read:", packetCount)
	fmt.Println("Unique devices found:", len(devices))
	fmt.Println()

	for mac, dev := range devices {
		fmt.Printf("MAC: %-20s IP: %s\n", mac, dev.IP)
	}
}