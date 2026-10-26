package fingerprints

import "strings"

// GuessTypeFromVendor makes a low-confidence guess at device type
// based on the vendor name alone.
func GuessTypeFromVendor(vendor string) string {
	v := strings.ToLower(vendor)

	switch {
	case strings.Contains(v, "hikvision"), strings.Contains(v, "dahua"), strings.Contains(v, "axis"):
		return "ip_camera"
	case strings.Contains(v, "linksys"), strings.Contains(v, "netgear"), strings.Contains(v, "tp-link"), strings.Contains(v, "cisco"):
		return "router"
	case strings.Contains(v, "hp"), strings.Contains(v, "canon"), strings.Contains(v, "epson"), strings.Contains(v, "brother"):
		return "printer"
	case strings.Contains(v, "apple"), strings.Contains(v, "samsung"), strings.Contains(v, "google"):
		return "phone"
	case strings.Contains(v, "raspberry pi"):
		return "iot_device"
	default:
		return "unknown"
	}
}