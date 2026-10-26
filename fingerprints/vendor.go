package fingerprints

import "strings"

// A small starter list of MAC prefix -> vendor name.
// (Later: replace/extend with the full IEEE OUI list.)
var vendorPrefixes = map[string]string{
	"00:D0:59": "Entrust Datacard",
	"00:0C:41": "Cisco-Linksys",
	"B8:27:EB": "Raspberry Pi Foundation",
	"DC:A6:32": "Raspberry Pi Trading",
	"00:1A:11": "Google",
	"3C:5A:B4": "Google",
	"F4:F5:D8": "Google",
	"00:17:88": "Philips Lighting (Hue)",
	"44:19:B6": "Hangzhou Hikvision",
	"00:1E:C0": "Hangzhou Hikvision",
}

// LookupVendor returns the vendor name for a MAC address, or "" if unknown.
func LookupVendor(mac string) string {
	mac = strings.ToUpper(mac)
	if len(mac) < 8 {
		return ""
	}
	prefix := mac[0:8] // e.g. "00:D0:59"

	if vendor, ok := vendorPrefixes[prefix]; ok {
		return vendor
	}
	return ""
}