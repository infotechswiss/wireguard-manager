package model

import (
	"time"
)

// Client represents a WireGuard client configuration.
type Client struct {
	// ID is a unique identifier for the client.
	ID string `json:"id"`

	// PrivateKey is the client's private key used for encryption.
	// It may be empty if the public key was provided externally.
	PrivateKey string `json:"private_key"`

	// PublicKey is the client's public key.
	PublicKey string `json:"public_key"`

	// PresharedKey is an optional key used to enhance security.
	PresharedKey string `json:"preshared_key"`

	// Name is the friendly name assigned to the client.
	Name string `json:"name"`

	// Email is the email address associated with the client.
	Email string `json:"email"`

	// SubnetRanges holds the names of subnet ranges from which the client’s IPs were allocated.
	// This field is omitted from JSON output if empty.
	SubnetRanges []string `json:"subnet_ranges,omitempty"`

	// AllocatedIPs is the list of IP addresses allocated to the client.
	AllocatedIPs []string `json:"allocated_ips"`

	// AllowedIPs defines the CIDR ranges that are allowed to route traffic.
	AllowedIPs []string `json:"allowed_ips"`

	// ExtraAllowedIPs defines additional CIDR ranges allowed for routing.
	ExtraAllowedIPs []string `json:"extra_allowed_ips"`

	// Endpoint specifies the client's endpoint configuration.
	Endpoint string `json:"endpoint"`

	// AdditionalNotes are optional notes or comments about the client.
	AdditionalNotes string `json:"additional_notes"`

	// UseServerDNS indicates whether the client should use the server's DNS settings.
	UseServerDNS bool `json:"use_server_dns"`

	// Enabled indicates if the client is currently active.
	Enabled bool `json:"enabled"`

	// CreatedAt is the timestamp when the client was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp of the client's last update.
	UpdatedAt time.Time `json:"updated_at"`
}

// ClientData wraps a Client with additional related data.
type ClientData struct {
	// Client holds the client's configuration.
	Client *Client

	// QRCode is a base64-encoded representation of the client's configuration QR code.
	QRCode string
}

// QRCodeSettings defines options for generating a QR code for a client.
type QRCodeSettings struct {
	// Enabled indicates whether QR code generation is enabled.
	Enabled bool

	// IncludeDNS specifies whether DNS settings should be included in the QR code.
	IncludeDNS bool

	// IncludeMTU specifies whether MTU settings should be included in the QR code.
	IncludeMTU bool
}
