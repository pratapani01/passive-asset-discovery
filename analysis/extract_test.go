package analysis

import (
	"net"
	"testing"
)

func TestIsPrivateMAC(t *testing.T) {
	cases := []struct {
		mac  string
		want bool
	}{
		{"66:00:ab:02:df:f7", true},
		{"22:a1:40:1f:a2:1f", true},
		{"48:68:4a:71:b4:e8", false},
		{"04:70:56:f8:63:87", false},
		{"not a mac", false},
		{"", false},
	}

	for _, c := range cases {
		if got := IsPrivateMAC(c.mac); got != c.want {
			t.Errorf("IsPrivateMAC(%q) = %v, want %v", c.mac, got, c.want)
		}
	}
}

func TestValidSenderMAC(t *testing.T) {
	cases := []struct {
		mac  string
		want bool
	}{
		{"48:68:4a:71:b4:e8", true},
		{"ff:ff:ff:ff:ff:ff", false},
		{"01:00:5e:00:00:fb", false},
		{"00:00:00:00:00:00", false},
	}

	for _, c := range cases {
		hw, err := net.ParseMAC(c.mac)
		if err != nil {
			t.Fatal(err)
		}
		if got := validSenderMAC(hw); got != c.want {
			t.Errorf("validSenderMAC(%s) = %v, want %v", c.mac, got, c.want)
		}
	}

	if validSenderMAC(net.HardwareAddr{0x01, 0x02}) {
		t.Error("a MAC that is not 6 bytes long must be rejected")
	}
}

func TestCleanText(t *testing.T) {
	if got := cleanText([]byte("  Johns-iPhone\x00\x07 "), 64); got != "Johns-iPhone" {
		t.Errorf("control characters and spaces should be stripped, got %q", got)
	}
	if got := cleanText([]byte("abcdefghij"), 4); got != "abcd" {
		t.Errorf("text should be cut to the limit, got %q", got)
	}
	if got := cleanText([]byte{0xff, 0xfe, 'o', 'k'}, 64); got != "ok" {
		t.Errorf("invalid UTF-8 should be dropped, got %q", got)
	}
}

func TestHeaderValues(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nServer: App-webs/\r\nContent-Type: text/html\r\nServer: ignored\r\n")
	headers := headerValues(raw)

	if got := headers["server"]; got != "App-webs/" {
		t.Errorf("server header = %q, want the first value App-webs/", got)
	}
	if got := headers["content-type"]; got != "text/html" {
		t.Errorf("content-type header = %q", got)
	}
}
