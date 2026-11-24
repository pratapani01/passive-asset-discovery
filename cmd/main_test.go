package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"passive-asset-discovery/capture"
)

var timeZero = time.Unix(1700000000, 0)

func trackerFromFile(t *testing.T, path string) *Tracker {
	t.Helper()

	src, err := capture.NewPCAPSource(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	tracker := NewTracker()
	if err := readPackets(src, tracker); err != nil {
		t.Logf("capture ended early: %v", err)
	}
	return tracker
}

func TestNTPSampleDevices(t *testing.T) {
	assets := trackerFromFile(t, "../testdata/NTP_sync.pcap").Snapshot()

	want := []struct{ mac, ip string }{
		{"00:0c:41:82:b2:53", "192.168.0.1"},
		{"00:d0:59:6c:40:4e", "192.168.50.50"},
	}
	if len(assets) != len(want) {
		t.Fatalf("found %d devices, want %d", len(assets), len(want))
	}
	for i, w := range want {
		if assets[i].MAC != w.mac || assets[i].IP != w.ip {
			t.Errorf("device %d = %s / %s, want %s / %s", i, assets[i].MAC, assets[i].IP, w.mac, w.ip)
		}
	}
}

func TestDNSSampleDevices(t *testing.T) {
	assets := trackerFromFile(t, "../testdata/dns-remoteshell.pcap").Snapshot()

	want := []struct{ mac, ip string }{
		{"00:0e:35:78:0c:02", "192.168.1.3"},
		{"00:80:48:24:33:32", "192.168.1.2"},
		{"00:90:d0:eb:46:e7", "192.168.1.1"},
	}
	if len(assets) != len(want) {
		t.Fatalf("found %d devices, want %d", len(assets), len(want))
	}
	for i, w := range want {
		if assets[i].MAC != w.mac || assets[i].IP != w.ip {
			t.Errorf("device %d = %s / %s, want %s / %s", i, assets[i].MAC, assets[i].IP, w.mac, w.ip)
		}
	}
}

func TestOutputIsDeterministicAndHasNoNulls(t *testing.T) {
	tracker := trackerFromFile(t, "../testdata/dns-remoteshell.pcap")

	first, err := json.Marshal(tracker.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(first), "null") {
		t.Errorf("JSON output must not contain null: %s", first)
	}

	for i := 0; i < 25; i++ {
		next, err := json.Marshal(tracker.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		if string(next) != string(first) {
			t.Fatalf("snapshot %d differs from the first one, output is not deterministic", i)
		}
	}
}

func TestCombine(t *testing.T) {
	cases := []struct {
		current, confidence, guess string
		wantType, wantConfidence   string
	}{
		{"unknown", "low", "printer", "printer", "medium"},
		{"printer", "low", "printer", "printer", "high"},
		{"printer", "medium", "ip_camera", "printer", "medium"},
		{"unknown", "low", "unknown", "unknown", "low"},
		{"unknown", "low", "", "unknown", "low"},
		{"router", "high", "router", "router", "high"},
	}

	for _, c := range cases {
		gotType, gotConfidence := combine(c.current, c.confidence, c.guess)
		if gotType != c.wantType || gotConfidence != c.wantConfidence {
			t.Errorf("combine(%q, %q, %q) = (%q, %q), want (%q, %q)",
				c.current, c.confidence, c.guess, gotType, gotConfidence, c.wantType, c.wantConfidence)
		}
	}
}

func TestGatewayAndPrivateMAC(t *testing.T) {
	tracker := NewTracker()
	tracker.gatewayMAC = "04:70:56:f8:63:87"

	tracker.entry("04:70:56:f8:63:87", timeZero).setIP("192.168.29.1")
	tracker.entry("02:11:22:33:44:55", timeZero).setIP("192.168.29.50")

	byMAC := map[string]string{}
	for _, a := range tracker.Snapshot() {
		byMAC[a.MAC] = a.DeviceType + "/" + a.Confidence + "/" + strings.Join(a.Evidence, ",")
	}

	if got := byMAC["04:70:56:f8:63:87"]; got != "router/high/mac oui,default gateway" {
		t.Errorf("gateway with a router vendor = %q", got)
	}
	if got := byMAC["02:11:22:33:44:55"]; got != "unknown/low/private (random) mac" {
		t.Errorf("random MAC device = %q", got)
	}

	tracker.gatewayMAC = "02:11:22:33:44:55"
	for _, a := range tracker.Snapshot() {
		if a.MAC == "02:11:22:33:44:55" && (a.DeviceType != "router" || a.Confidence != "medium") {
			t.Errorf("gateway with no other clue should be router/medium, got %s/%s", a.DeviceType, a.Confidence)
		}
	}
}

func TestOpenPortsAreListedInOrder(t *testing.T) {
	tracker := NewTracker()
	d := tracker.entry("48:68:4a:71:b4:e8", timeZero)
	d.setIP("192.168.29.210")
	d.ports[443] = true
	d.ports[80] = true

	assets := tracker.Snapshot()
	if len(assets) != 1 {
		t.Fatalf("found %d devices, want 1", len(assets))
	}

	got := strings.Join(assets[0].Evidence, ",")
	want := "mac oui,open port 80/tcp,open port 443/tcp"
	if got != want {
		t.Errorf("evidence = %q, want %q", got, want)
	}
}

func TestNetworkSubnet(t *testing.T) {
	cases := []struct {
		name       string
		gatewayIP  string
		mask       net.IPMask
		wantSubnet string
		wantSource string
	}{
		{"assumed /24", "192.168.29.1", nil, "192.168.29.0/24", "assumed /24"},
		{"from dhcp /25", "192.168.29.200", net.CIDRMask(25, 32), "192.168.29.128/25", "dhcp"},
		{"from dhcp /16", "10.1.2.3", net.CIDRMask(16, 32), "10.1.0.0/16", "dhcp"},
	}

	for _, c := range cases {
		tracker := NewTracker()
		tracker.gatewayMAC = "04:70:56:f8:63:87"
		tracker.subnetMask = c.mask
		tracker.entry("04:70:56:f8:63:87", timeZero).setIP(c.gatewayIP)

		info := tracker.Network()
		if info.Subnet != c.wantSubnet || info.SubnetSource != c.wantSource || info.Gateway != c.gatewayIP {
			t.Errorf("%s: got subnet %q (%s) gateway %q, want %q (%s) gateway %q",
				c.name, info.Subnet, info.SubnetSource, info.Gateway, c.wantSubnet, c.wantSource, c.gatewayIP)
		}
	}

	empty := NewTracker().Network()
	if empty.Subnet != "" || empty.Gateway != "" {
		t.Errorf("an empty tracker should report no subnet or gateway, got %+v", empty)
	}
}
