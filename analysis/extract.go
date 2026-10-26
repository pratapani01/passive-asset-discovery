package analysis

import (
	"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DeviceInfo holds what we learned about one device from a packet.
type DeviceInfo struct {
	IP  string
	MAC string
}

// ExtractDevice pulls IP and MAC addresses out of a single packet.
// Returns ok=false if the packet doesn't have useful info.
func ExtractDevice(packet gopacket.Packet) (DeviceInfo, bool) {
	var info DeviceInfo
	found := false

	// MAC address: comes from the Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		info.MAC = eth.SrcMAC.String()
		found = true
	}

	// IP address: comes from the IPv4 layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.IP = ip.SrcIP.String()
		found = true
	}

	return info, found
}
// DHCPHostname checks if this packet is a DHCP request with a hostname,
// and returns (hostname, evidence string, true) if found.
func DHCPHostname(packet gopacket.Packet) (string, string, bool) {
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		return "", "", false
	}

	dhcp, ok := dhcpLayer.(*layers.DHCPv4)
	if !ok {
		return "", "", false
	}

	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptHostname {
			return string(opt.Data), "dhcp hostname", true
		}
	}

	return "", "", false
}
// MDNSClue checks if this packet is an mDNS announcement and returns
// a device-type guess and evidence string, if recognized.
func MDNSClue(packet gopacket.Packet) (string, string, bool) {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return "", "", false
	}

	payload := string(appLayer.Payload())

	switch {
	case strings.Contains(payload, "_ipp._tcp"), strings.Contains(payload, "_printer._tcp"):
		return "printer", "mdns _ipp._tcp", true
	case strings.Contains(payload, "_rtsp._tcp"):
		return "ip_camera", "mdns _rtsp._tcp", true
	case strings.Contains(payload, "_airplay._tcp"), strings.Contains(payload, "_raop._tcp"):
		return "tv_or_speaker", "mdns _airplay._tcp", true
	case strings.Contains(payload, "_http._tcp"):
		return "unknown", "mdns _http._tcp", true
	}

	return "", "", false
}