package fingerprints

import "testing"

func TestLookupVendor(t *testing.T) {
	cases := []struct {
		mac  string
		want string
	}{
		{"00:0c:41:82:b2:53", "Cisco-Linksys, LLC"},
		{"00-D0-59-6C-40-4E", "AMBIT MICROSYSTEMS CORP."},
		{"04:70:56:f8:63:87", "Arcadyan Corporation"},
		{"48:68:4a:71:b4:e8", "Intel Corporate"},
		{"66:00:ab:02:df:f7", ""},
		{"zz:zz:zz:zz:zz:zz", ""},
		{"00:0c", ""},
		{"", ""},
	}

	for _, c := range cases {
		if got := LookupVendor(c.mac); got != c.want {
			t.Errorf("LookupVendor(%q) = %q, want %q", c.mac, got, c.want)
		}
	}
}

func TestVendorCount(t *testing.T) {
	if n := VendorCount(); n < 30000 {
		t.Errorf("VendorCount() = %d, the embedded OUI list looks truncated", n)
	}
}

func TestGuessTypeFromVendor(t *testing.T) {
	cases := []struct {
		vendor string
		want   string
	}{
		{"Hangzhou Hikvision Digital Technology Co.,Ltd.", "ip_camera"},
		{"Axis Communications AB", "ip_camera"},
		{"Cisco-Linksys, LLC", "router"},
		{"Arcadyan Corporation", "router"},
		{"Seiko Epson Corporation", "printer"},
		{"Raspberry Pi Trading Ltd", "iot_device"},
		{"Taxis Holdings", "unknown"},
		{"Intel Corporate", "unknown"},
		{"", "unknown"},
	}

	for _, c := range cases {
		if got := GuessTypeFromVendor(c.vendor); got != c.want {
			t.Errorf("GuessTypeFromVendor(%q) = %q, want %q", c.vendor, got, c.want)
		}
	}
}

func TestGuessTypeFromBanner(t *testing.T) {
	cases := []struct {
		banner string
		want   string
	}{
		{"App-webs/", "ip_camera"},
		{"Hikvision-Webs", "ip_camera"},
		{"CUPS/2.4 IPP/2.1", "printer"},
		{"Linux/3.0 UPnP/1.0 miniupnpd/1.8", "router"},
		{"nginx", "unknown"},
		{"", "unknown"},
	}

	for _, c := range cases {
		if got := GuessTypeFromBanner(c.banner); got != c.want {
			t.Errorf("GuessTypeFromBanner(%q) = %q, want %q", c.banner, got, c.want)
		}
	}
}

func TestGuessTypeFromHostname(t *testing.T) {
	cases := []struct {
		hostname string
		want     string
	}{
		{"motorola-edge-50-fusion", "phone"},
		{"Johns-iPhone", "phone"},
		{"Galaxy-S23", "phone"},
		{"HP-Printer-3F", "printer"},
		{"DESKTOP-AB12CD", "computer"},
		{"IPCAM-front-door", "ip_camera"},
		{"esp_1a2b3c", "unknown"},
		{"", "unknown"},
	}

	for _, c := range cases {
		if got := GuessTypeFromHostname(c.hostname); got != c.want {
			t.Errorf("GuessTypeFromHostname(%q) = %q, want %q", c.hostname, got, c.want)
		}
	}
}

func TestMatchMDNSService(t *testing.T) {
	cases := []struct {
		names       []string
		wantType    string
		wantService string
		wantFound   bool
	}{
		{[]string{"_ipp._tcp.local"}, "printer", "_ipp._tcp", true},
		{[]string{"_ipps._tcp.local"}, "printer", "_ipps._tcp", true},
		{[]string{"HP LaserJet._printer._tcp.local"}, "printer", "_printer._tcp", true},
		{[]string{"_rtsp._tcp.local"}, "ip_camera", "_rtsp._tcp", true},
		{[]string{"_googlecast._tcp.local"}, "tv_or_speaker", "_googlecast._tcp", true},
		{[]string{"_http._tcp.local"}, "unknown", "_http._tcp", true},
		{[]string{"somehost.local"}, "", "", false},
		{nil, "", "", false},
	}

	for _, c := range cases {
		gotType, gotService, found := MatchMDNSService(c.names)
		if gotType != c.wantType || gotService != c.wantService || found != c.wantFound {
			t.Errorf("MatchMDNSService(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.names, gotType, gotService, found, c.wantType, c.wantService, c.wantFound)
		}
	}
}

func TestMatchSSDP(t *testing.T) {
	cases := []struct {
		text      string
		wantType  string
		wantFound bool
	}{
		{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", "router", true},
		{"urn:schemas-upnp-org:device:MediaRenderer:1", "tv_or_speaker", true},
		{"urn:dial-multiscreen-org:service:dial:1", "tv_or_speaker", true},
		{"upnp:rootdevice", "", false},
		{"", "", false},
	}

	for _, c := range cases {
		gotType, _, found := MatchSSDP(c.text)
		if gotType != c.wantType || found != c.wantFound {
			t.Errorf("MatchSSDP(%q) = (%q, %v), want (%q, %v)",
				c.text, gotType, found, c.wantType, c.wantFound)
		}
	}
}

func TestHasWordRespectsBoundaries(t *testing.T) {
	if hasWord("Taxis Holdings", "axis") {
		t.Error("axis must not match inside Taxis")
	}
	if !hasWord("Axis Communications", "axis") {
		t.Error("axis should match at the start of a name")
	}
	if !hasWord("Cisco-Linksys", "linksys") {
		t.Error("linksys should match after a hyphen")
	}
}
