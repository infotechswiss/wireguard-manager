package model

import "time"

// GlobalSetting represents the global configuration settings for the WireGuard server.
// Note: Some numeric values (e.g., MTU, PersistentKeepalive) are expected as strings in JSON.
type GlobalSetting struct {
	EndpointAddress     string    `json:"endpoint_address"`            // The external endpoint address of the WireGuard server.
	DNSServers          []string  `json:"dns_servers"`                 // List of DNS servers for client configuration.
	MTU                 int       `json:"mtu,string"`                  // Maximum Transmission Unit; JSON provides this value as a string.
	PersistentKeepalive int       `json:"persistent_keepalive,string"` // Keepalive interval (seconds); provided as a string in JSON.
	FirewallMark        string    `json:"firewall_mark"`               // Firewall mark used for routing.
	Table               string    `json:"table"`                       // Routing table identifier.
	ConfigFilePath      string    `json:"config_file_path"`            // File path where the WireGuard config is generated.
	UpdatedAt           time.Time `json:"updated_at"`                  // Timestamp of the last update to the settings.
}
