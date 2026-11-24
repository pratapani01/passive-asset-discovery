package analysis

import (
	"bytes"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"passive-asset-discovery/fingerprints"
)

const (
	mdnsPort = 5353
	ssdpPort = 1900
)

func udpPayload(packet gopacket.Packet, port layers.UDPPort) ([]byte, bool) {
	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || (udp.SrcPort != port && udp.DstPort != port) {
		return nil, false
	}
	return udp.Payload, true
}

func parseMDNSResponse(packet gopacket.Packet) (*layers.DNS, bool) {
	payload, ok := udpPayload(packet, mdnsPort)
	if !ok {
		return nil, false
	}

	var dns layers.DNS
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil || !dns.QR {
		return nil, false
	}
	return &dns, true
}

func mdnsRecords(dns *layers.DNS) []layers.DNSResourceRecord {
	records := make([]layers.DNSResourceRecord, 0, len(dns.Answers)+len(dns.Additionals))
	records = append(records, dns.Answers...)
	return append(records, dns.Additionals...)
}

func MDNSClue(packet gopacket.Packet) (string, string, bool) {
	dns, ok := parseMDNSResponse(packet)
	if !ok {
		return "", "", false
	}

	var names []string
	for _, rr := range mdnsRecords(dns) {
		names = append(names, string(rr.Name))
		if rr.Type == layers.DNSTypePTR {
			names = append(names, string(rr.PTR))
		}
	}

	deviceType, service, found := fingerprints.MatchMDNSService(names)
	if !found {
		return "", "", false
	}
	return deviceType, "mdns " + service, true
}

func MDNSHostname(packet gopacket.Packet) (string, bool) {
	dns, ok := parseMDNSResponse(packet)
	if !ok {
		return "", false
	}

	for _, rr := range mdnsRecords(dns) {
		if rr.Type != layers.DNSTypeA && rr.Type != layers.DNSTypeAAAA {
			continue
		}

		host, found := strings.CutSuffix(string(rr.Name), ".local")
		if !found || strings.HasPrefix(host, "_") || strings.Contains(host, ".") {
			continue
		}
		if name := cleanText([]byte(host), 64); name != "" {
			return name, true
		}
	}
	return "", false
}

func HTTPBannerClue(packet gopacket.Packet) (string, string, bool) {
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !bytes.HasPrefix(tcp.Payload, []byte("HTTP/")) {
		return "", "", false
	}

	head := tcp.Payload
	if len(head) > 2048 {
		head = head[:2048]
	}
	if end := bytes.Index(head, []byte("\r\n\r\n")); end >= 0 {
		head = head[:end]
	}

	if server, found := headerValues(head)["server"]; found {
		if banner := cleanText([]byte(server), 80); banner != "" {
			return banner, "http banner: " + banner, true
		}
	}
	return "", "", false
}

func SSDPClue(packet gopacket.Packet) (string, string, bool) {
	payload, ok := udpPayload(packet, ssdpPort)
	if !ok {
		return "", "", false
	}
	if !bytes.HasPrefix(payload, []byte("NOTIFY ")) && !bytes.HasPrefix(payload, []byte("HTTP/1.1 200")) {
		return "", "", false
	}
	if len(payload) > 2048 {
		payload = payload[:2048]
	}

	headers := headerValues(payload)
	text := strings.Join([]string{headers["nt"], headers["st"], headers["usn"], headers["server"]}, " ")

	if deviceType, token, found := fingerprints.MatchSSDP(text); found {
		return deviceType, "ssdp " + token, true
	}
	if server := cleanText([]byte(headers["server"]), 80); server != "" {
		return fingerprints.GuessTypeFromBanner(server), "ssdp server: " + server, true
	}
	return "", "", false
}

func headerValues(head []byte) map[string]string {
	values := make(map[string]string)

	for _, line := range bytes.Split(head, []byte("\r\n")) {
		name, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(string(name)))
		if _, seen := values[key]; !seen {
			values[key] = strings.TrimSpace(string(value))
		}
	}
	return values
}
