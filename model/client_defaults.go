package model

// ClientDefaults holds the default settings for creating new clients.
// These defaults are used in the templates when rendering client creation forms.
type ClientDefaults struct {
	AllowedIPs          []string `json:"allowed_ips"`           // Default allowed IP ranges.
	ExtraAllowedIPs     []string `json:"extra_allowed_ips"`     // Additional allowed IP ranges.
	UseServerDNS        bool     `json:"use_server_dns"`        // Whether to use the server's DNS settings.
	EnableAfterCreation bool     `json:"enable_after_creation"` // Whether the client is enabled immediately after creation.
}
