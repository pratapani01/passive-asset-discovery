package analysis

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PublicSourceMAC returns the sender's MAC when the packet came from a public
// internet IP. On a home network only the router forwards such packets, so
// that MAC is the default gateway.
func PublicSourceMAC(packet gopacket.Packet) (string, bool) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ethLayer == nil || ipLayer == nil {
		return "", false
	}
	eth, ok1 := ethLayer.(*layers.Ethernet)
	ip, ok2 := ipLayer.(*layers.IPv4)
	if !ok1 || !ok2 {
		return "", false
	}

	src := ip.SrcIP
	if src.IsPrivate() || src.IsUnspecified() || src.IsMulticast() ||
		src.IsLoopback() || src.IsLinkLocalUnicast() {
		return "", false
	}
	return eth.SrcMAC.String(), true
}

// OpenPortClue returns the sender's port when a TCP SYN-ACK is seen.
// A SYN-ACK means the sender accepted a connection, so that port is open.
func OpenPortClue(packet gopacket.Packet) (int, bool) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return 0, false
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return 0, false
	}
	if tcp.SYN && tcp.ACK {
		return int(tcp.SrcPort), true
	}
	return 0, false
}

// IsPrivateMAC reports whether a MAC is a random "private" address.
// Phones set a special bit in the first byte when they randomize the MAC.
func IsPrivateMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) == 0 {
		return false
	}
	return hw[0]&0x02 != 0
}
