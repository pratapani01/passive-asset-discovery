package analysis

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func PublicSourceMAC(packet gopacket.Packet) (string, bool) {
	eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok || !validSenderMAC(eth.SrcMAC) {
		return "", false
	}

	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return "", false
	}

	src := ip.SrcIP
	if src.IsPrivate() || src.IsUnspecified() || src.IsMulticast() || src.IsLoopback() ||
		src.IsLinkLocalUnicast() || src.Equal(net.IPv4bcast) {
		return "", false
	}

	return eth.SrcMAC.String(), true
}

func OpenPortClue(packet gopacket.Packet) (int, bool) {
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !tcp.SYN || !tcp.ACK {
		return 0, false
	}
	return int(tcp.SrcPort), true
}

func IsPrivateMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) == 0 {
		return false
	}
	return hw[0]&0x02 != 0
}
