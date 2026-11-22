package main

import (
	"fmt"
	"time"

	"passive-asset-discovery/analysis"
	"passive-asset-discovery/capture"
)

func main() {
	src, err := capture.NewLiveSource(`C:\Program Files\Wireshark\tshark.exe`, "Wi-Fi")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer src.Close()

	fmt.Println("Listening for 30 seconds...")
	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		packet, err := src.Next()
		if err != nil {
			fmt.Println("Stopped:", err)
			return
		}
		if info, ok := analysis.ExtractDevice(packet); ok {
			fmt.Println("MAC:", info.MAC, "IP:", info.IP)
		}
	}
	fmt.Println("Done")
}
