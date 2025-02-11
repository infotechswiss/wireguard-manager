package store

import (
	"github.com/swissmakers/wireguard-manager/model"
)

// IStore defines the interface for data storage used in the application.
// It abstracts the methods for user management, server configuration,
// client management, and hash tracking.
type IStore interface {
	// Initialization
	Init() error

	// User Management
	GetUsers() ([]model.User, error)
	GetUserByName(username string) (model.User, error)
	SaveUser(user model.User) error
	DeleteUser(username string) error

	// Global Settings and Server Configuration
	GetGlobalSettings() (model.GlobalSetting, error)
	GetServer() (model.Server, error)
	SaveServerInterface(serverInterface model.ServerInterface) error
	SaveServerKeyPair(serverKeyPair model.ServerKeypair) error
	SaveGlobalSettings(globalSettings model.GlobalSetting) error

	// Client Management
	GetClients(hasQRCode bool) ([]model.ClientData, error)
	GetClientByID(clientID string, qrCode model.QRCodeSettings) (model.ClientData, error)
	SaveClient(client model.Client) error
	DeleteClient(clientID string) error

	// File Storage Path
	GetPath() string

	// Hash Management for Config Change Detection
	SaveHashes(hashes model.ClientServerHashes) error
	GetHashes() (model.ClientServerHashes, error)
}
