package analysis

// Asset matches the exact JSON shape required by the project spec.
type Asset struct {
	IP         string   `json:"ip"`
	MAC        string   `json:"mac"`
	Vendor     string   `json:"vendor"`
	DeviceType string   `json:"device_type"`
	Confidence string   `json:"confidence"`
	Hostname   string   `json:"hostname,omitempty"`
	Evidence   []string `json:"evidence"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   string   `json:"last_seen"`
}