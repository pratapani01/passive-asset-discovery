package main

import (
	"fmt"
	"os"

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

	count := 0
	for {
		packet, err := src.Next()
		if err != nil {
			break // file khatam ho gayi
		}
		count++
		fmt.Println("Packet", count, "-", packet.String()[:80], "...")
	}

	fmt.Println("\nTotal packets read:", count)
}