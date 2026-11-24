package analysis

import (
	"bytes"
	"net"
	"strings"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DeviceInfo struct {
	IP  string
	MAC string
}

func validSenderMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&0x01 != 0 {
		return false
	}
	return !bytes.Equal(mac, make([]byte, 6))
}

func cleanText(raw []byte, limit int) string {
	s := strings.ToValidUTF8(string(raw), "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	s = strings.TrimSpace(s)

	if runes := []rune(s); len(runes) > limit {
		s = string(runes[:limit])
	}
	return s
}

func ExtractDevice(packet gopacket.Packet) (DeviceInfo, bool) {
	eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok || !validSenderMAC(eth.SrcMAC) {
		return DeviceInfo{}, false
	}

	info := DeviceInfo{MAC: eth.SrcMAC.String()}

	if ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok && ip.SrcIP.IsPrivate() {
		info.IP = ip.SrcIP.String()
	}

	return info, true
}

func ARPClue(packet gopacket.Packet) (string, string, bool) {
	arp, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	if !ok || len(arp.SourceHwAddress) != 6 || len(arp.SourceProtAddress) != 4 {
		return "", "", false
	}

	mac := net.HardwareAddr(arp.SourceHwAddress)
	ip := net.IP(arp.SourceProtAddress)
	if !validSenderMAC(mac) || !ip.IsPrivate() {
		return "", "", false
	}

	return mac.String(), ip.String(), true
}

func dhcpMessage(packet gopacket.Packet, op layers.DHCPOp) (*layers.DHCPv4, bool) {
	dhcp, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	if !ok || dhcp.Operation != op {
		return nil, false
	}
	return dhcp, true
}

func dhcpOption(dhcp *layers.DHCPv4, code layers.DHCPOpt) ([]byte, bool) {
	for _, opt := range dhcp.Options {
		if opt.Type == code {
			return opt.Data, true
		}
	}
	return nil, false
}

func DHCPHostname(packet gopacket.Packet) (string, string, bool) {
	dhcp, ok := dhcpMessage(packet, layers.DHCPOpRequest)
	if !ok {
		return "", "", false
	}

	data, found := dhcpOption(dhcp, layers.DHCPOptHostname)
	if !found {
		return "", "", false
	}

	name := cleanText(data, 64)
	if name == "" {
		return "", "", false
	}
	return name, "dhcp hostname", true
}

func DHCPRequestedIP(packet gopacket.Packet) (string, bool) {
	dhcp, ok := dhcpMessage(packet, layers.DHCPOpRequest)
	if !ok {
		return "", false
	}

	data, found := dhcpOption(dhcp, layers.DHCPOptRequestIP)
	if !found || len(data) != 4 || !net.IP(data).IsPrivate() {
		return "", false
	}
	return net.IP(data).String(), true
}

func DHCPSubnetMask(packet gopacket.Packet) (net.IPMask, bool) {
	dhcp, ok := dhcpMessage(packet, layers.DHCPOpReply)
	if !ok {
		return nil, false
	}

	data, found := dhcpOption(dhcp, layers.DHCPOptSubnetMask)
	if !found || len(data) != 4 {
		return nil, false
	}

	mask := net.IPMask(append([]byte(nil), data...))
	if ones, bits := mask.Size(); bits != 32 || ones == 0 {
		return nil, false
	}
	return mask, true
}
