package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"os"
)

// PCAPSource reads packets from a .pcap file.
type PCAPSource struct {
	file   *os.File
	reader *pcapgo.Reader
	source *gopacket.PacketSource
}

// NewPCAPSource opens a pcap file and gets it ready to read.
func NewPCAPSource(path string) (*PCAPSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}

	ps := gopacket.NewPacketSource(r, r.LinkType())

	return &PCAPSource{
		file:   f,
		reader: r,
		source: ps,
	}, nil
}

// Next returns the next packet, or an error (io.EOF when the file ends).
func (p *PCAPSource) Next() (gopacket.Packet, error) {
	return p.source.NextPacket()
}

// Close closes the underlying file.
func (p *PCAPSource) Close() error {
	return p.file.Close()
}