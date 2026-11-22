package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"

	"passive-asset-discovery/analysis"
	"passive-asset-discovery/capture"
	"passive-asset-discovery/fingerprints"
)

const tsharkPath = `C:\Program Files\Wireshark\tshark.exe`

// Tracker collects everything we learn about each device.
// The mutex protects shared data between packet capture and web server.
type Tracker struct {
	mu          sync.Mutex
	devices     map[string]analysis.DeviceInfo
	firstSeen   map[string]time.Time
	lastSeen    map[string]time.Time
	hostnames   map[string]string
	evidenceMap map[string][]string
	mdnsGuess   map[string]string
	httpGuess   map[string]string

	ports      map[string]map[int]bool
	gatewayMAC string
}

func NewTracker() *Tracker {
	return &Tracker{
		devices:     make(map[string]analysis.DeviceInfo),
		firstSeen:   make(map[string]time.Time),
		lastSeen:    make(map[string]time.Time),
		hostnames:   make(map[string]string),
		evidenceMap: make(map[string][]string),
		mdnsGuess:   make(map[string]string),
		httpGuess:   make(map[string]string),

		ports: make(map[string]map[int]bool),
	}
}

func (t *Tracker) addEvidence(mac, ev string) {
	for _, e := range t.evidenceMap[mac] {
		if e == ev {
			return
		}
	}

	t.evidenceMap[mac] = append(t.evidenceMap[mac], ev)
}

// setIP records an IP for a MAC if we don't have one yet.
func (t *Tracker) setIP(mac, ip string, ts time.Time) {
	dev, seen := t.devices[mac]

	if !seen {
		t.devices[mac] = analysis.DeviceInfo{
			MAC: mac,
			IP:  ip,
		}
		t.firstSeen[mac] = ts
		t.lastSeen[mac] = ts
		return
	}

	if dev.IP == "" {
		dev.IP = ip
		t.devices[mac] = dev
	}
}

// Add learns from one packet.
func (t *Tracker) Add(packet gopacket.Packet) {
	info, ok := analysis.ExtractDevice(packet)
	if !ok || info.MAC == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Detect gateway MAC
	if gw, ok := analysis.PublicSourceMAC(packet); ok {
		t.gatewayMAC = gw
	}

	// Collect TCP port clues
	// Only count devices having an IP address
	if info.IP != "" {
		if port, ok := analysis.OpenPortClue(packet); ok {
			if t.ports[info.MAC] == nil {
				t.ports[info.MAC] = make(map[int]bool)
			}
			t.ports[info.MAC][port] = true
		}
	}

	ts := packet.Metadata().Timestamp

	existing, seen := t.devices[info.MAC]
	if !seen {
		t.devices[info.MAC] = info
		t.firstSeen[info.MAC] = ts
	} else if existing.IP == "" && info.IP != "" {
		t.devices[info.MAC] = info
	}

	t.lastSeen[info.MAC] = ts

	// ARP IP discovery
	if mac, ip, ok := analysis.ARPClue(packet); ok {
		t.setIP(mac, ip, ts)
	}

	// DHCP requested IP discovery
	if ip, ok := analysis.DHCPRequestedIP(packet); ok {
		t.setIP(info.MAC, ip, ts)
	}

	// DHCP hostname discovery
	if hostname, ev, ok := analysis.DHCPHostname(packet); ok {
		t.hostnames[info.MAC] = hostname
		t.addEvidence(info.MAC, ev)
	}

	// mDNS identification
	if guess, ev, ok := analysis.MDNSClue(packet); ok {
		t.addEvidence(info.MAC, ev)

		if guess != "unknown" {
			t.mdnsGuess[info.MAC] = guess
		}
	}

	// HTTP banner identification
	if banner, ev, ok := analysis.HTTPBannerClue(packet); ok {
		t.addEvidence(info.MAC, ev)

		guess := fingerprints.GuessTypeFromBanner(banner)
		if guess != "unknown" {
			t.httpGuess[info.MAC] = guess
		}
	}
}

// Snapshot builds the current sorted device list.
func (t *Tracker) Snapshot() []analysis.Asset {
	t.mu.Lock()
	defer t.mu.Unlock()

	assets := []analysis.Asset{}

	for mac, dev := range t.devices {
		vendor := fingerprints.LookupVendor(mac)

		evidence := append([]string{}, t.evidenceMap[mac]...)

		if vendor != "" {
			evidence = append(evidence, "mac oui")
		}

		deviceType := "unknown"
		confidence := "low"

		// Vendor-based identification
		if vendor != "" {
			if guessed := fingerprints.GuessTypeFromVendor(vendor); guessed != "unknown" {
				deviceType = guessed
			}
		}

		// mDNS identification
		if mg, ok := t.mdnsGuess[mac]; ok {
			if deviceType == "unknown" {
				deviceType = mg
				confidence = "medium"
			} else if mg == deviceType {
				confidence = "high"
			}
		}

		// HTTP banner identification
		if hg, ok := t.httpGuess[mac]; ok {
			if deviceType == "unknown" {
				deviceType = hg
				confidence = "medium"
			} else if hg == deviceType {
				confidence = "high"
			}
		}

		// Hostname identification
		if t.hostnames[mac] != "" {
			if ht := fingerprints.GuessTypeFromHostname(t.hostnames[mac]); ht != "unknown" {
				if deviceType == "unknown" {
					deviceType = ht
					confidence = "medium"
				} else if ht == deviceType {
					confidence = "high"
				}
			}
		}

		// Add port evidence
		ports := []int{}

		for p := range t.ports[mac] {
			ports = append(ports, p)
		}

		sort.Ints(ports)

		for _, p := range ports {
			evidence = append(
				evidence,
				fmt.Sprintf("open port %d/tcp", p),
			)
		}

		// Identify private/random MAC
		if analysis.IsPrivateMAC(mac) {
			evidence = append(evidence, "private (random) mac")
		}

		// Identify gateway
		if t.gatewayMAC != "" && mac == t.gatewayMAC {
			evidence = append(evidence, "default gateway")

			if deviceType == "unknown" {
				deviceType = "router"
				confidence = "medium"
			}
		}

		assets = append(assets, analysis.Asset{
			IP:         dev.IP,
			MAC:        mac,
			Vendor:     vendor,
			DeviceType: deviceType,
			Confidence: confidence,
			Hostname:   t.hostnames[mac],
			Evidence:   evidence,
			FirstSeen:  t.firstSeen[mac].UTC().Format(time.RFC3339),
			LastSeen:   t.lastSeen[mac].UTC().Format(time.RFC3339),
		})
	}

	sort.Slice(assets, func(i, j int) bool {
		return assets[i].MAC < assets[j].MAC
	})

	return assets
}

// NetworkInfo contains a summary of the discovered network.
type NetworkInfo struct {
	Subnet      string `json:"subnet"`
	Gateway     string `json:"gateway"`
	GatewayMAC  string `json:"gateway_mac"`
	DeviceCount int    `json:"device_count"`
}

// Network summarises the network.
// Subnet assumes a /24, which is typical for a home router.
func (t *Tracker) Network() NetworkInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	info := NetworkInfo{
		GatewayMAC:  t.gatewayMAC,
		DeviceCount: len(t.devices),
	}

	if gw, ok := t.devices[t.gatewayMAC]; ok && gw.IP != "" {
		info.Gateway = gw.IP

		if ip := net.ParseIP(gw.IP).To4(); ip != nil {
			info.Subnet = fmt.Sprintf(
				"%d.%d.%d.0/24",
				ip[0], ip[1], ip[2],
			)
		}
	}

	return info
}

// readPackets feeds every packet from the source to the tracker.
// For a file it ends at the end of the file; for live it runs until stopped.
func readPackets(src capture.PacketSource, t *Tracker) {
	for {
		packet, err := src.Next()
		if err != nil {
			return
		}

		t.Add(packet)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  go run ./cmd/main.go <file.pcap>")
		fmt.Println("  go run ./cmd/main.go live [interface-name]")
		os.Exit(1)
	}

	tracker := NewTracker()

	if os.Args[1] == "live" {
		iface := "Wi-Fi"

		if len(os.Args) >= 3 {
			iface = os.Args[2]
		}

		src, err := capture.NewLiveSource(tsharkPath, iface)
		if err != nil {
			fmt.Println("Error starting live capture:", err)
			os.Exit(1)
		}

		defer src.Close()

		go readPackets(src, tracker)

		fmt.Println("Listening live on:", iface, "(passive only)")
	} else {
		src, err := capture.NewPCAPSource(os.Args[1])
		if err != nil {
			fmt.Println("Error opening pcap:", err)
			os.Exit(1)
		}

		readPackets(src, tracker)
		src.Close()

		out, _ := json.MarshalIndent(tracker.Snapshot(), "", "  ")
		fmt.Println(string(out))
	}

	// Assets endpoint
	http.HandleFunc("/assets.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		out, err := json.MarshalIndent(tracker.Snapshot(), "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(out)
	})

	// Network summary endpoint
	http.HandleFunc("/network.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		json.NewEncoder(w).Encode(tracker.Network())
	})

	// Serve dashboard
	http.Handle("/", http.FileServer(http.Dir("web")))

	fmt.Println("Viewer: http://localhost:8080/viewer.html  (Ctrl+C to stop)")
	http.ListenAndServe(":8080", nil)
}
