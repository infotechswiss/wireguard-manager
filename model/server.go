package model

import "time"

// Server represents the overall WireGuard server configuration,
// containing both the key pair and the network interface settings.
type Server struct {
	KeyPair   *ServerKeypair   `json:"keypair"`   // The server's key pair used for encryption.
	Interface *ServerInterface `json:"interface"` // The server's network interface configuration.
}

// ServerKeypair holds the cryptographic keys for the server.
type ServerKeypair struct {
	PrivateKey string    `json:"private_key"` // The server's private key (should be kept secret).
	PublicKey  string    `json:"public_key"`  // The corresponding public key.
	UpdatedAt  time.Time `json:"updated_at"`  // Timestamp of the last key update.
}

// ServerInterface contains the network interface configuration for the server.
type ServerInterface struct {
	Addresses  []string  `json:"addresses"`          // CIDR addresses assigned to the interface.
	ListenPort int       `json:"listen_port,string"` // Port on which the server listens (input as string in JSON, converted to int).
	UpdatedAt  time.Time `json:"updated_at"`         // Timestamp of the last update to the interface configuration.
	PostUp     string    `json:"post_up"`            // Command to run after the interface is brought up.
	PreDown    string    `json:"pre_down"`           // Command to run before the interface is brought down.
	PostDown   string    `json:"post_down"`          // Command to run after the interface is brought down.
}
