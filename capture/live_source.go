package capture

import (
	"io"
	"os/exec"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// LiveSource listens to a network interface by running tshark and reading
// the pcap stream it prints. Same PacketSource interface, so the analysis
// code does not change. Passive only: it never sends anything.
type LiveSource struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	source *gopacket.PacketSource
}

func NewLiveSource(tsharkPath, iface string) (*LiveSource, error) {
	cmd := exec.Command(tsharkPath, "-i", iface, "-l", "-F", "pcap", "-w", "-")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	r, err := pcapgo.NewReader(stdout)
	if err != nil {
		cmd.Process.Kill()
		return nil, err
	}

	ps := gopacket.NewPacketSource(r, r.LinkType())
	return &LiveSource{cmd: cmd, stdout: stdout, source: ps}, nil
}

// Next blocks until the next packet arrives on the network.
func (l *LiveSource) Next() (gopacket.Packet, error) {
	return l.source.NextPacket()
}

// Close stops tshark.
func (l *LiveSource) Close() error {
	if l.cmd.Process != nil {
		l.cmd.Process.Kill()
	}
	l.cmd.Wait()
	return nil
}
