package capture

import (
	"github.com/google/gopacket"
)

// PacketSource hands packets one at a time to whatever reads them.
// Today: a PCAP file. Later: a live network card (someone else's job).
type PacketSource interface {
	Next() (gopacket.Packet, error)
	Close() error
}