package capture

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

const maxDiagnosticBytes = 4096

type diagnosticBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (d *diagnosticBuffer) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if room := maxDiagnosticBytes - d.buf.Len(); room > 0 {
		if len(p) > room {
			d.buf.Write(p[:room])
		} else {
			d.buf.Write(p)
		}
	}
	return len(p), nil
}

func (d *diagnosticBuffer) String() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.TrimSpace(d.buf.String())
}

type LiveSource struct {
	cmd    *exec.Cmd
	source *gopacket.PacketSource
	stderr *diagnosticBuffer
	once   sync.Once
}

func DefaultInterface() string {
	switch runtime.GOOS {
	case "windows":
		return "Wi-Fi"
	case "darwin":
		return "en0"
	default:
		return ""
	}
}

func FindTshark(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("tshark not found at %s", explicit)
		}
		return explicit, nil
	}

	if path, err := exec.LookPath("tshark"); err == nil {
		return path, nil
	}

	defaults := []string{
		`C:\Program Files\Wireshark\tshark.exe`,
		`C:\Program Files (x86)\Wireshark\tshark.exe`,
		"/Applications/Wireshark.app/Contents/MacOS/tshark",
	}
	for _, path := range defaults {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", errors.New("tshark not found: install Wireshark or pass -tshark <path>")
}

func NewLiveSource(tsharkPath, iface string) (*LiveSource, error) {
	if iface == "" || strings.HasPrefix(iface, "-") {
		return nil, fmt.Errorf("invalid interface name %q", iface)
	}

	cmd := exec.Command(tsharkPath, "-i", iface, "-l", "-F", "pcap", "-w", "-")
	stderr := &diagnosticBuffer{}
	cmd.Stderr = stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot start %s: %w", tsharkPath, err)
	}

	reader, err := pcapgo.NewReader(stdout)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		reason := stderr.String()
		if reason == "" {
			reason = err.Error()
		}
		return nil, fmt.Errorf("tshark could not capture on %q: %s", iface, reason)
	}

	return &LiveSource{
		cmd:    cmd,
		source: gopacket.NewPacketSource(reader, reader.LinkType()),
		stderr: stderr,
	}, nil
}

func (l *LiveSource) Next() (gopacket.Packet, error) {
	return l.source.NextPacket()
}

func (l *LiveSource) Diagnostics() string {
	return l.stderr.String()
}

func (l *LiveSource) Close() error {
	l.once.Do(func() {
		if l.cmd.Process != nil {
			l.cmd.Process.Kill()
		}
		l.cmd.Wait()
	})
	return nil
}
