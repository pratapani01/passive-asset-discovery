package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var pcapngMagic = []byte{0x0a, 0x0d, 0x0d, 0x0a}

type linkReader interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
}

type PCAPSource struct {
	file   *os.File
	source *gopacket.PacketSource
}

func NewPCAPSource(path string) (*PCAPSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	buffered := bufio.NewReaderSize(f, 1<<20)
	magic, err := buffered.Peek(len(pcapngMagic))
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s is not a capture file: %w", path, err)
	}

	var reader linkReader
	if bytes.Equal(magic, pcapngMagic) {
		reader, err = pcapgo.NewNgReader(buffered, pcapgo.DefaultNgReaderOptions)
	} else {
		reader, err = pcapgo.NewReader(buffered)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	source := gopacket.NewPacketSource(reader, reader.LinkType())
	source.DecodeOptions = gopacket.Lazy

	return &PCAPSource{file: f, source: source}, nil
}

func (p *PCAPSource) Next() (gopacket.Packet, error) {
	return p.source.NextPacket()
}

func (p *PCAPSource) Close() error {
	return p.file.Close()
}
