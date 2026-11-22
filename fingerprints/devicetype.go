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

// GuessTypeFromBanner makes a guess based on an HTTP Server banner text.
func GuessTypeFromBanner(banner string) string {
	b := strings.ToLower(banner)

	switch {
	case strings.Contains(b, "hikvision"), strings.Contains(b, "ipcam"), strings.Contains(b, "dahua"):
		return "ip_camera"
	case strings.Contains(b, "cups"), strings.Contains(b, "printer"):
		return "printer"
	case strings.Contains(b, "router"), strings.Contains(b, "openwrt"), strings.Contains(b, "dd-wrt"):
		return "router"
	default:
		return "unknown"
	}
}

// GuessTypeFromHostname guesses device type from a DHCP hostname.
func GuessTypeFromHostname(hostname string) string {
	h := strings.ToLower(hostname)

	switch {
	case strings.Contains(h, "iphone"), strings.Contains(h, "ipad"), strings.Contains(h, "android"),
		strings.Contains(h, "galaxy"), strings.Contains(h, "motorola"), strings.Contains(h, "redmi"),
		strings.Contains(h, "oneplus"), strings.Contains(h, "pixel"), strings.Contains(h, "realme"):
		return "phone"
	case strings.Contains(h, "printer"), strings.Contains(h, "epson"), strings.Contains(h, "brother"):
		return "printer"
	case strings.Contains(h, "ipcam"), strings.Contains(h, "camera"), strings.Contains(h, "hikvision"):
		return "ip_camera"
	case strings.Contains(h, "macbook"), strings.Contains(h, "laptop-"), strings.Contains(h, "desktop-"):
		return "computer"
	default:
		return "unknown"
	}
}
