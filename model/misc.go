package model

// Interface represents a network interface with its name and IP address.
type Interface struct {
	Name      string `json:"name"`       // Name of the interface (e.g., "eth0").
	IPAddress string `json:"ip_address"` // IP address assigned to the interface.
}

// BaseData contains common data to be passed to templates.
// This includes the current active page, the current user's name, and whether they have admin privileges.
type BaseData struct {
	Active      string // The currently active page or section.
	CurrentUser string // The username of the currently logged-in user.
	Admin       bool   // Flag indicating if the current user has admin privileges.
}

// ClientServerHashes holds hash values for client and server configurations.
// These hashes are used to detect changes in the configuration data.
type ClientServerHashes struct {
	Client string `json:"client"` // Hash for the client configuration.
	Server string `json:"server"` // Hash for the server configuration.
}
