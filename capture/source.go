package capture

import "github.com/google/gopacket"

type PacketSource interface {
	Next() (gopacket.Packet, error)
	Close() error
}
