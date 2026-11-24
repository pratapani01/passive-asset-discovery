package fingerprints

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.txt
var ouiData string

var (
	ouiOnce  sync.Once
	ouiTable map[string]string
)

func loadOUI() {
	ouiTable = make(map[string]string, 40000)

	for _, line := range strings.Split(ouiData, "\n") {
		idx := strings.Index(line, "(hex)")
		if idx < 0 {
			continue
		}

		prefix := normalizeHex(line[:idx])
		if len(prefix) != 6 {
			continue
		}

		if name := strings.TrimSpace(line[idx+len("(hex)"):]); name != "" {
			ouiTable[prefix] = name
		}
	}
}

func normalizeHex(s string) string {
	var b strings.Builder

	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			b.WriteRune(r)
		case r >= 'a' && r <= 'f':
			b.WriteRune(r - 'a' + 'A')
		case r == ':', r == '-', r == '.', r == ' ', r == '\t', r == '\r':
		default:
			return ""
		}
	}

	return b.String()
}

func LookupVendor(mac string) string {
	ouiOnce.Do(loadOUI)

	hex := normalizeHex(mac)
	if len(hex) < 6 {
		return ""
	}

	return ouiTable[hex[:6]]
}

func VendorCount() int {
	ouiOnce.Do(loadOUI)
	return len(ouiTable)
}
