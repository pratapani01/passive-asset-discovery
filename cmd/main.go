package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"

	"passive-asset-discovery/analysis"
	"passive-asset-discovery/capture"
	"passive-asset-discovery/fingerprints"
	"passive-asset-discovery/web"
)

type device struct {
	ip        string
	firstSeen time.Time
	lastSeen  time.Time
	hostname  string
	evidence  []string
	ports     map[int]bool
	mdnsGuess string
	httpGuess string
	ssdpGuess string
}

func (d *device) addEvidence(ev string) {
	for _, e := range d.evidence {
		if e == ev {
			return
		}
	}
	d.evidence = append(d.evidence, ev)
}

func (d *device) setIP(ip string) {
	if d.ip == "" {
		d.ip = ip
	}
}

type Tracker struct {
	mu         sync.Mutex
	devices    map[string]*device
	gatewayMAC string
	subnetMask net.IPMask
}

func NewTracker() *Tracker {
	return &Tracker{devices: make(map[string]*device)}
}

func (t *Tracker) entry(mac string, ts time.Time) *device {
	d, ok := t.devices[mac]
	if !ok {
		d = &device{firstSeen: ts, lastSeen: ts, ports: make(map[int]bool)}
		t.devices[mac] = d
	}
	return d
}

func keepKnown(current, guess string) string {
	if guess == "" || guess == "unknown" {
		return current
	}
	return guess
}

func combine(current, confidence, guess string) (string, string) {
	if guess == "" || guess == "unknown" {
		return current, confidence
	}
	if current == "unknown" {
		return guess, "medium"
	}
	if guess == current {
		return current, "high"
	}
	return current, confidence
}

func (t *Tracker) Add(packet gopacket.Packet) {
	info, ok := analysis.ExtractDevice(packet)
	if !ok {
		return
	}
	ts := packet.Metadata().Timestamp

	t.mu.Lock()
	defer t.mu.Unlock()

	if mac, ok := analysis.PublicSourceMAC(packet); ok {
		t.gatewayMAC = mac
	}
	if mask, ok := analysis.DHCPSubnetMask(packet); ok {
		t.subnetMask = mask
	}

	d := t.entry(info.MAC, ts)
	d.lastSeen = ts

	if info.IP != "" {
		d.setIP(info.IP)
		if port, ok := analysis.OpenPortClue(packet); ok {
			d.ports[port] = true
		}
	}

	if mac, ip, ok := analysis.ARPClue(packet); ok {
		t.entry(mac, ts).setIP(ip)
	}
	if ip, ok := analysis.DHCPRequestedIP(packet); ok {
		d.setIP(ip)
	}

	if name, ev, ok := analysis.DHCPHostname(packet); ok {
		d.hostname = name
		d.addEvidence(ev)
	}
	if name, ok := analysis.MDNSHostname(packet); ok && d.hostname == "" {
		d.hostname = name
		d.addEvidence("mdns hostname")
	}

	if guess, ev, ok := analysis.MDNSClue(packet); ok {
		d.addEvidence(ev)
		d.mdnsGuess = keepKnown(d.mdnsGuess, guess)
	}
	if banner, ev, ok := analysis.HTTPBannerClue(packet); ok {
		d.addEvidence(ev)
		d.httpGuess = keepKnown(d.httpGuess, fingerprints.GuessTypeFromBanner(banner))
	}
	if guess, ev, ok := analysis.SSDPClue(packet); ok {
		d.addEvidence(ev)
		d.ssdpGuess = keepKnown(d.ssdpGuess, guess)
	}
}

func (t *Tracker) Snapshot() []analysis.Asset {
	t.mu.Lock()
	defer t.mu.Unlock()

	assets := make([]analysis.Asset, 0, len(t.devices))

	for mac, d := range t.devices {
		vendor := fingerprints.LookupVendor(mac)
		evidence := append([]string{}, d.evidence...)

		deviceType, confidence := "unknown", "low"
		if vendor != "" {
			evidence = append(evidence, "mac oui")
			if guess := fingerprints.GuessTypeFromVendor(vendor); guess != "unknown" {
				deviceType = guess
			}
		}

		hostnameGuess := ""
		if d.hostname != "" {
			hostnameGuess = fingerprints.GuessTypeFromHostname(d.hostname)
		}
		for _, guess := range []string{d.mdnsGuess, d.httpGuess, d.ssdpGuess, hostnameGuess} {
			deviceType, confidence = combine(deviceType, confidence, guess)
		}

		ports := make([]int, 0, len(d.ports))
		for p := range d.ports {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		for _, p := range ports {
			evidence = append(evidence, fmt.Sprintf("open port %d/tcp", p))
		}

		if analysis.IsPrivateMAC(mac) {
			evidence = append(evidence, "private (random) mac")
		}

		if t.gatewayMAC != "" && mac == t.gatewayMAC {
			evidence = append(evidence, "default gateway")
			deviceType, confidence = combine(deviceType, confidence, "router")
		}

		assets = append(assets, analysis.Asset{
			IP:         d.ip,
			MAC:        mac,
			Vendor:     vendor,
			DeviceType: deviceType,
			Confidence: confidence,
			Hostname:   d.hostname,
			Evidence:   evidence,
			FirstSeen:  d.firstSeen.UTC().Format(time.RFC3339),
			LastSeen:   d.lastSeen.UTC().Format(time.RFC3339),
		})
	}

	sort.Slice(assets, func(i, j int) bool { return assets[i].MAC < assets[j].MAC })
	return assets
}

type NetworkInfo struct {
	Subnet       string `json:"subnet"`
	SubnetSource string `json:"subnet_source"`
	Gateway      string `json:"gateway"`
	GatewayMAC   string `json:"gateway_mac"`
	DeviceCount  int    `json:"device_count"`
}

func (t *Tracker) Network() NetworkInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	info := NetworkInfo{GatewayMAC: t.gatewayMAC, DeviceCount: len(t.devices)}

	gw, ok := t.devices[t.gatewayMAC]
	if !ok || gw.ip == "" {
		return info
	}
	info.Gateway = gw.ip

	ip := net.ParseIP(gw.ip).To4()
	if ip == nil {
		return info
	}

	mask, source := t.subnetMask, "dhcp"
	if mask == nil {
		mask, source = net.CIDRMask(24, 32), "assumed /24"
	}
	ones, _ := mask.Size()
	info.Subnet = fmt.Sprintf("%s/%d", ip.Mask(mask), ones)
	info.SubnetSource = source
	return info
}

func readPackets(src capture.PacketSource, t *Tracker) error {
	for {
		packet, err := src.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		t.Add(packet)
	}
}

func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := encodeJSON(w, v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage:
  passive-scan [flags] <capture.pcap | capture.pcapng>
  passive-scan [flags] live [interface]

Flags:
`)
	flag.PrintDefaults()
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "address the web viewer listens on")
	tshark := flag.String("tshark", "", "path to tshark (live mode only, found automatically if empty)")
	noWeb := flag.Bool("no-web", false, "capture file mode: print the JSON and exit without starting the viewer")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	tracker := NewTracker()
	stop := func() {}

	if args[0] == "live" {
		iface := capture.DefaultInterface()
		if len(args) > 1 {
			iface = args[1]
		}
		if iface == "" {
			fatal("no default interface on this system, pass one (for example: passive-scan live wlan0). List them with: tshark -D")
		}

		tsharkBin, err := capture.FindTshark(*tshark)
		if err != nil {
			fatal(err.Error())
		}
		src, err := capture.NewLiveSource(tsharkBin, iface)
		if err != nil {
			fatal(err.Error())
		}

		stop = func() { src.Close() }

		go func() {
			err := readPackets(src, tracker)
			msg := "capture stopped"
			if err != nil {
				msg += ": " + err.Error()
			}
			if diag := src.Diagnostics(); diag != "" {
				msg += " (" + diag + ")"
			}
			fmt.Fprintln(os.Stderr, msg)
		}()

		fmt.Fprintf(os.Stderr, "Listening on %s (passive, nothing is sent)\n", iface)
	} else {
		src, err := capture.NewPCAPSource(args[0])
		if err != nil {
			fatal(err.Error())
		}
		err = readPackets(src, tracker)
		src.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: capture ended early:", err)
		}

		if err := encodeJSON(os.Stdout, tracker.Snapshot()); err != nil {
			fatal(err.Error())
		}
		if *noWeb {
			return
		}
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupt
		stop()
		os.Exit(0)
	}()

	files := http.FileServer(http.FS(web.Files))
	mux := http.NewServeMux()
	mux.HandleFunc("/assets.json", func(w http.ResponseWriter, r *http.Request) {
		writeResponse(w, tracker.Snapshot())
	})
	mux.HandleFunc("/network.json", func(w http.ResponseWriter, r *http.Request) {
		writeResponse(w, tracker.Network())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/viewer.html", http.StatusFound)
			return
		}
		files.ServeHTTP(w, r)
	})

	shown := *addr
	if strings.HasPrefix(shown, ":") {
		shown = "localhost" + shown
	}
	fmt.Fprintf(os.Stderr, "Viewer: http://%s/viewer.html (Ctrl+C to stop)\n", shown)

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		stop()
		fatal(err.Error())
	}
}
