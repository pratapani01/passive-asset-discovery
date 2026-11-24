package fingerprints

import "strings"

type typeRule struct {
	deviceType string
	words      []string
}

var vendorRules = []typeRule{
	{"ip_camera", []string{"hikvision", "dahua", "axis", "reolink", "amcrest", "foscam", "vivotek"}},
	{"router", []string{"linksys", "netgear", "tp-link", "d-link", "mikrotik", "ubiquiti", "zyxel", "arcadyan"}},
	{"printer", []string{"epson", "brother", "lexmark", "kyocera", "ricoh", "xerox", "canon"}},
	{"iot_device", []string{"raspberry", "espressif", "tuya"}},
}

var bannerRules = []typeRule{
	{"ip_camera", []string{"hikvision", "ipcam", "dahua", "app-webs", "dnvrs-webs"}},
	{"printer", []string{"cups", "printer"}},
	{"router", []string{"router", "openwrt", "dd-wrt", "miniupnpd", "routeros"}},
}

var hostnameRules = []typeRule{
	{"phone", []string{"iphone", "ipad", "android", "galaxy", "motorola", "redmi", "oneplus", "pixel", "realme"}},
	{"printer", []string{"printer", "epson", "brother"}},
	{"ip_camera", []string{"ipcam", "camera", "hikvision"}},
	{"computer", []string{"macbook", "laptop-", "desktop-"}},
}

var mdnsRules = []typeRule{
	{"printer", []string{"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"}},
	{"ip_camera", []string{"_rtsp._tcp"}},
	{"tv_or_speaker", []string{"_googlecast._tcp"}},
	{"unknown", []string{"_http._tcp"}},
}

var ssdpRules = []typeRule{
	{"router", []string{"InternetGatewayDevice", "WANConnectionDevice"}},
	{"printer", []string{"Printer"}},
	{"tv_or_speaker", []string{"MediaRenderer", "dial-multiscreen-org", "roku"}},
	{"ip_camera", []string{"NetworkCamera"}},
}

func hasWord(text, word string) bool {
	text = strings.ToLower(text)

	for start := 0; start < len(text); {
		i := strings.Index(text[start:], word)
		if i < 0 {
			return false
		}
		i += start
		end := i + len(word)

		if (i == 0 || !isAlnum(text[i-1])) && (end == len(text) || !isAlnum(text[end])) {
			return true
		}
		start = i + 1
	}

	return false
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func matchWords(rules []typeRule, text string) string {
	for _, rule := range rules {
		for _, word := range rule.words {
			if hasWord(text, word) {
				return rule.deviceType
			}
		}
	}
	return "unknown"
}

func matchSubstrings(rules []typeRule, text string) string {
	text = strings.ToLower(text)

	for _, rule := range rules {
		for _, word := range rule.words {
			if strings.Contains(text, word) {
				return rule.deviceType
			}
		}
	}
	return "unknown"
}

func GuessTypeFromVendor(vendor string) string {
	return matchWords(vendorRules, vendor)
}

func GuessTypeFromBanner(banner string) string {
	return matchSubstrings(bannerRules, banner)
}

func GuessTypeFromHostname(hostname string) string {
	return matchSubstrings(hostnameRules, hostname)
}

func MatchMDNSService(names []string) (string, string, bool) {
	for _, rule := range mdnsRules {
		for _, service := range rule.words {
			for _, name := range names {
				if strings.Contains(strings.ToLower(name), service) {
					return rule.deviceType, service, true
				}
			}
		}
	}
	return "", "", false
}

func MatchSSDP(text string) (string, string, bool) {
	lower := strings.ToLower(text)

	for _, rule := range ssdpRules {
		for _, token := range rule.words {
			if strings.Contains(lower, strings.ToLower(token)) {
				return rule.deviceType, token, true
			}
		}
	}
	return "", "", false
}
