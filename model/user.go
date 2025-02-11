package model

import (
	"encoding/json"
)

// User represents a user in the system.
// Note: The PasswordHash field takes precedence over Password.
type User struct {
	Username     string `json:"username"`
	Password     string `json:"password"`      // Used for binding input only.
	PasswordHash string `json:"password_hash"` // Preferred field for authentication.
	Admin        bool   `json:"admin"`
}

// MarshalJSON customizes the JSON encoding for User.
// It omits the plain-text Password field when marshalling, so that sensitive data is not leaked.
func (u User) MarshalJSON() ([]byte, error) {
	// Define an alias to avoid infinite recursion.
	type Alias User
	return json.Marshal(&struct {
		Password string `json:"password,omitempty"`
		*Alias
	}{
		// Always output an empty string for Password.
		Password: "",
		Alias:    (*Alias)(&u),
	})
}
