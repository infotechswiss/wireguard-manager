package handler

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/rs/xid"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/swissmakers/wireguard-manager/emailer"
	"github.com/swissmakers/wireguard-manager/model"
	"github.com/swissmakers/wireguard-manager/store"
	"github.com/swissmakers/wireguard-manager/util"
)

var usernameRegexp = regexp.MustCompile(`^\w[\w\-.]*$`)

//
// Request payload structures
//

type loginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	RememberMe bool   `json:"rememberMe"`
}

type updateUserRequest struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
	PreviousUsername string `json:"previous_username"`
	Admin            bool   `json:"admin"`
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Admin    bool   `json:"admin"`
}

type removeUserRequest struct {
	Username string `json:"username"`
}

type setClientStatusRequest struct {
	ID     string `json:"id"`
	Status bool   `json:"status"`
}

//
// Handlers
//

// Health check handler
func Health() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}
}

func Favicon() echo.HandlerFunc {
	return func(c echo.Context) error {
		if favicon, ok := os.LookupEnv(util.FaviconFilePathEnvVar); ok {
			return c.File(favicon)
		}
		return c.Redirect(http.StatusFound, util.BasePath+"/static/custom/img/favicon.ico")
	}
}

// LoginPage handler renders the login page.
func LoginPage() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "login.html", map[string]interface{}{})
	}
}

// Login handler for signing in.
func Login(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req loginRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Invalid login data"})
		}

		ip := c.Request().RemoteAddr
		if util.Proxy {
			ip = c.Request().Header.Get("X-FORWARDED-FOR")
		}

		// Validate username format
		if !usernameRegexp.MatchString(req.Username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid username"})
		}

		dbuser, err := db.GetUserByName(req.Username)
		if err != nil {
			log.Warnf("Invalid credentials. Cannot query user %s from DB (%s)", req.Username, ip)
			// Do not leak details about why login failed.
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Invalid credentials"})
		}

		// Constant-time username comparison
		userCorrect := subtle.ConstantTimeCompare([]byte(req.Username), []byte(dbuser.Username)) == 1

		var passwordCorrect bool
		if dbuser.PasswordHash != "" {
			match, err := util.VerifyHash(dbuser.PasswordHash, req.Password)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot verify password"})
			}
			passwordCorrect = match
		} else {
			passwordCorrect = subtle.ConstantTimeCompare([]byte(req.Password), []byte(dbuser.Password)) == 1
		}

		if userCorrect && passwordCorrect {
			var ageMax int
			if req.RememberMe {
				ageMax = 86400 * 7
			}

			cookiePath := util.GetCookiePath()

			// Get session
			sess, err := session.Get("session", c)
			if err != nil {
				log.Error("Failed to get session: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Internal server error"})
			}

			sess.Options = &sessions.Options{
				Path:     cookiePath,
				MaxAge:   ageMax,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}

			// Set session values
			tokenUID := xid.New().String()
			now := time.Now().UTC().Unix()
			sess.Values["username"] = dbuser.Username
			sess.Values["user_hash"] = util.GetDBUserCRC32(dbuser)
			sess.Values["admin"] = dbuser.Admin
			sess.Values["session_token"] = tokenUID
			sess.Values["max_age"] = ageMax
			sess.Values["created_at"] = now
			sess.Values["updated_at"] = now

			if err := sess.Save(c.Request(), c.Response()); err != nil {
				log.Error("Failed to save session: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Internal server error"})
			}

			// Also set session_token cookie
			cookie := &http.Cookie{
				Name:     "session_token",
				Path:     cookiePath,
				Value:    tokenUID,
				MaxAge:   ageMax,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
			c.SetCookie(cookie)

			log.Infof("Logged in successfully user %s (%s)", req.Username, ip)
			return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Logged in successfully"})
		}

		log.Warnf("Invalid credentials user %s (%s)", req.Username, ip)
		return c.JSON(http.StatusUnauthorized, jsonHTTPResponse{Success: false, Message: "Invalid credentials"})
	}
}

// GetUsers handler returns a JSON list of all users.
func GetUsers(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		usersList, err := db.GetUsers()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				Success: false, Message: fmt.Sprintf("Cannot get user list: %v", err),
			})
		}
		return c.JSON(http.StatusOK, usersList)
	}
}

// GetUser handler returns a JSON object of a single user.
func GetUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		username := c.Param("username")
		if !usernameRegexp.MatchString(username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid username"})
		}
		if !isAdmin(c) && (username != currentUser(c)) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{Success: false, Message: "Manager cannot access other user data"})
		}
		userData, err := db.GetUserByName(username)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{Success: false, Message: "User not found"})
		}
		return c.JSON(http.StatusOK, userData)
	}
}

// Logout handler logs a user out.
func Logout() echo.HandlerFunc {
	return func(c echo.Context) error {
		clearSession(c)
		return c.Redirect(http.StatusTemporaryRedirect, util.BasePath+"/login")
	}
}

// LoadProfile handler to load user profile information.
func LoadProfile() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "profile.html", map[string]interface{}{
			"baseData": model.BaseData{
				Active:      "profile",
				CurrentUser: currentUser(c),
				Admin:       isAdmin(c),
			},
		})
	}
}

// UsersSettings handler renders the users settings page.
func UsersSettings() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "users_settings.html", map[string]interface{}{
			"baseData": model.BaseData{
				Active:      "users-settings",
				CurrentUser: currentUser(c),
				Admin:       isAdmin(c),
			},
		})
	}
}

// UpdateUser handler updates user information.
func UpdateUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req updateUserRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Bad post data"})
		}

		// Only admin (or the same user) can update data.
		if !isAdmin(c) && (req.PreviousUsername != currentUser(c)) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{Success: false, Message: "Manager cannot access other user data"})
		}

		// Non-admins cannot promote privileges.
		if !isAdmin(c) {
			req.Admin = false
		}

		if !usernameRegexp.MatchString(req.PreviousUsername) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid username"})
		}

		user, err := db.GetUserByName(req.PreviousUsername)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{Success: false, Message: err.Error()})
		}

		if req.Username == "" || !usernameRegexp.MatchString(req.Username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid username"})
		}
		user.Username = req.Username

		// Check if username is taken
		if req.Username != req.PreviousUsername {
			_, err := db.GetUserByName(req.Username)
			if err == nil {
				return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "This username is taken"})
			}
		}

		// Update password hash if provided.
		if req.Password != "" {
			hash, err := util.HashPassword(req.Password)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
			}
			user.PasswordHash = hash
		}

		// Only update admin field if the request is not from the current user.
		if req.PreviousUsername != currentUser(c) {
			user.Admin = req.Admin
		}

		// Replace user entry in DB.
		if err := db.DeleteUser(req.PreviousUsername); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		if err := db.SaveUser(user); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		log.Infof("Updated user information successfully")

		// Update session if the current user was changed.
		if req.PreviousUsername == currentUser(c) {
			setUser(c, user.Username, user.Admin, util.GetDBUserCRC32(user))
		}

		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Updated user information successfully"})
	}
}

// CreateUser handler creates a new user.
func CreateUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req createUserRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Bad post data"})
		}

		if req.Username == "" || !usernameRegexp.MatchString(req.Username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid username"})
		}

		// Check for existing user.
		if _, err := db.GetUserByName(req.Username); err == nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "This username is taken"})
		}

		hash, err := util.HashPassword(req.Password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}

		user := model.User{
			Username:     req.Username,
			PasswordHash: hash,
			Admin:        req.Admin,
		}

		if err := db.SaveUser(user); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		log.Infof("Created user successfully")
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Created user successfully"})
	}
}

// RemoveUser handler deletes a user.
func RemoveUser(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req removeUserRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Bad post data"})
		}

		if !usernameRegexp.MatchString(req.Username) {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid username"})
		}

		// Prevent users from deleting themselves.
		if req.Username == currentUser(c) {
			return c.JSON(http.StatusForbidden, jsonHTTPResponse{Success: false, Message: "User cannot delete itself"})
		}

		if err := db.DeleteUser(req.Username); err != nil {
			log.Error("Cannot delete user: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot delete user from database"})
		}

		log.Infof("Removed user: %s", req.Username)
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "User removed"})
	}
}

// WireGuardClients handler renders the WireGuard clients page.
func WireGuardClients(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientDataList, err := db.GetClients(true)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				Success: false, Message: fmt.Sprintf("Cannot get client list: %v", err),
			})
		}
		return c.Render(http.StatusOK, "clients.html", map[string]interface{}{
			"baseData":       model.BaseData{Active: "", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"clientDataList": clientDataList,
		})
	}
}

// GetClients handler returns a JSON list of WireGuard client data.
func GetClients(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientDataList, err := db.GetClients(true)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				Success: false, Message: fmt.Sprintf("Cannot get client list: %v", err),
			})
		}
		for i, clientData := range clientDataList {
			clientDataList[i] = util.FillClientSubnetRange(clientData)
		}
		return c.JSON(http.StatusOK, clientDataList)
	}
}

// GetClient handler returns a JSON object of WireGuard client data.
func GetClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientID := c.Param("id")
		if _, err := xid.FromString(clientID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid client ID"})
		}

		qrCodeSettings := model.QRCodeSettings{
			Enabled:    true,
			IncludeDNS: true,
			IncludeMTU: true,
		}

		clientData, err := db.GetClientByID(clientID, qrCodeSettings)
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{Success: false, Message: "Client not found"})
		}

		return c.JSON(http.StatusOK, util.FillClientSubnetRange(clientData))
	}
}

// NewClient handler creates a new WireGuard client.
func NewClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var client model.Client
		if err := c.Bind(&client); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Invalid client data"})
		}

		// Fetch server configuration.
		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot fetch server from database: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}

		// Validate allocation IPs.
		allocatedIPs, err := util.GetAllocatedIPs("")
		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: fmt.Sprintf("%s", err)})
		}
		if check, err := util.ValidateIPAllocation(server.Interface.Addresses, allocatedIPs, client.AllocatedIPs); !check {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: fmt.Sprintf("%s", err)})
		}

		// Validate AllowedIPs and ExtraAllowedIPs.
		if !util.ValidateAllowedIPs(client.AllowedIPs) {
			log.Warnf("Invalid Allowed IPs input from user: %v", client.AllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Allowed IPs must be in CIDR format"})
		}
		if !util.ValidateExtraAllowedIPs(client.ExtraAllowedIPs) {
			log.Warnf("Invalid Extra AllowedIPs input from user: %v", client.ExtraAllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Extra AllowedIPs must be in CIDR format"})
		}

		// Generate a new client ID.
		client.ID = xid.New().String()

		// Generate key pair if not provided.
		if client.PublicKey == "" {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				log.Error("Cannot generate wireguard key pair: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot generate WireGuard key pair"})
			}
			client.PrivateKey = key.String()
			client.PublicKey = key.PublicKey().String()
		} else {
			// Validate provided public key.
			if _, err := wgtypes.ParseKey(client.PublicKey); err != nil {
				log.Error("Cannot verify wireguard public key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot verify WireGuard public key"})
			}
			// Check for duplicate public keys.
			clients, err := db.GetClients(false)
			if err != nil {
				log.Error("Cannot get clients for duplicate check")
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot get clients for duplicate check"})
			}
			for _, other := range clients {
				if other.Client.PublicKey == client.PublicKey {
					log.Error("Duplicate Public Key")
					return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Duplicate Public Key"})
				}
			}
		}

		// Generate or validate PresharedKey.
		if client.PresharedKey == "" {
			presharedKey, err := wgtypes.GenerateKey()
			if err != nil {
				log.Error("Cannot generate preshared key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot generate WireGuard preshared key"})
			}
			client.PresharedKey = presharedKey.String()
		} else if client.PresharedKey == "-" {
			client.PresharedKey = ""
			log.Infof("Skipped PresharedKey generation for user: %v", client.Name)
		} else {
			if _, err := wgtypes.ParseKey(client.PresharedKey); err != nil {
				log.Error("Cannot verify wireguard preshared key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot verify WireGuard preshared key"})
			}
		}

		now := time.Now().UTC()
		client.CreatedAt = now
		client.UpdatedAt = now

		// Save client in the database.
		if err := db.SaveClient(client); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		log.Infof("Created wireguard client: %v", client.Name)
		return c.JSON(http.StatusOK, client)
	}
}

// EmailClient handler sends the configuration via email.
func EmailClient(db store.IStore, mailer emailer.Emailer, emailSubject, emailContent string) echo.HandlerFunc {
	type clientIdEmailPayload struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}

	return func(c echo.Context) error {
		var payload clientIdEmailPayload
		if err := c.Bind(&payload); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Invalid payload"})
		}

		if _, err := xid.FromString(payload.ID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid client ID"})
		}

		qrCodeSettings := model.QRCodeSettings{
			Enabled:    true,
			IncludeDNS: true,
			IncludeMTU: true,
		}
		clientData, err := db.GetClientByID(payload.ID, qrCodeSettings)
		if err != nil {
			log.Errorf("Cannot generate client config for id %s: %v", payload.ID, err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{Success: false, Message: "Client not found"})
		}

		// Build configuration.
		server, _ := db.GetServer()
		globalSettings, _ := db.GetGlobalSettings()
		config := util.BuildClientConfig(*clientData.Client, server, globalSettings)

		cfgAtt := emailer.Attachment{Name: "wg0.conf", Data: []byte(config)}
		var attachments []emailer.Attachment
		if clientData.Client.PrivateKey != "" {
			qrdata, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(clientData.QRCode, "data:image/png;base64,"))
			if err != nil {
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Decoding error: " + err.Error()})
			}
			qrAtt := emailer.Attachment{Name: "wg.png", Data: qrdata}
			attachments = []emailer.Attachment{cfgAtt, qrAtt}
		} else {
			attachments = []emailer.Attachment{cfgAtt}
		}

		if err := mailer.Send(
			clientData.Client.Name,
			payload.Email,
			emailSubject,
			emailContent,
			attachments,
		); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Email sent successfully"})
	}
}

// UpdateClient handler updates client information.
func UpdateClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var clientUpdate model.Client
		if err := c.Bind(&clientUpdate); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Invalid client data"})
		}

		if _, err := xid.FromString(clientUpdate.ID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid client ID"})
		}

		// Validate client existence.
		clientData, err := db.GetClientByID(clientUpdate.ID, model.QRCodeSettings{Enabled: false})
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{Success: false, Message: "Client not found"})
		}

		server, err := db.GetServer()
		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: fmt.Sprintf("Cannot fetch server config: %s", err)})
		}

		client := *clientData.Client
		allocatedIPs, err := util.GetAllocatedIPs(client.ID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: fmt.Sprintf("%s", err)})
		}
		if check, err := util.ValidateIPAllocation(server.Interface.Addresses, allocatedIPs, clientUpdate.AllocatedIPs); !check {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: fmt.Sprintf("%s", err)})
		}

		// Validate AllowedIPs and ExtraAllowedIPs.
		if !util.ValidateAllowedIPs(clientUpdate.AllowedIPs) {
			log.Warnf("Invalid Allowed IPs input: %v", clientUpdate.AllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Allowed IPs must be in CIDR format"})
		}
		if !util.ValidateExtraAllowedIPs(clientUpdate.ExtraAllowedIPs) {
			log.Warnf("Invalid Extra AllowedIPs input: %v", clientUpdate.ExtraAllowedIPs)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Extra Allowed IPs must be in CIDR format"})
		}

		// Update public key if changed.
		if client.PublicKey != clientUpdate.PublicKey && clientUpdate.PublicKey != "" {
			if _, err := wgtypes.ParseKey(clientUpdate.PublicKey); err != nil {
				log.Error("Cannot verify provided WireGuard public key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot verify provided WireGuard public key"})
			}
			clients, err := db.GetClients(false)
			if err != nil {
				log.Error("Cannot get client list for duplicate public key check")
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot get client list for duplicate public key check"})
			}
			for _, other := range clients {
				if other.Client.PublicKey == clientUpdate.PublicKey {
					log.Error("Duplicate Public Key")
					return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Duplicate Public Key"})
				}
			}
			// Discard the stored private key as it no longer matches.
			if client.PrivateKey != "" {
				client.PrivateKey = ""
			}
		}

		// Update preshared key if changed.
		if client.PresharedKey != clientUpdate.PresharedKey && clientUpdate.PresharedKey != "" {
			if _, err := wgtypes.ParseKey(clientUpdate.PresharedKey); err != nil {
				log.Error("Cannot verify provided WireGuard preshared key: ", err)
				return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot verify provided WireGuard preshared key"})
			}
		}

		// Map new data.
		client.Name = clientUpdate.Name
		client.Email = clientUpdate.Email
		client.Enabled = clientUpdate.Enabled
		client.UseServerDNS = clientUpdate.UseServerDNS
		client.AllocatedIPs = clientUpdate.AllocatedIPs
		client.AllowedIPs = clientUpdate.AllowedIPs
		client.ExtraAllowedIPs = clientUpdate.ExtraAllowedIPs
		client.Endpoint = clientUpdate.Endpoint
		client.PublicKey = clientUpdate.PublicKey
		client.PresharedKey = clientUpdate.PresharedKey
		client.UpdatedAt = time.Now().UTC()
		client.AdditionalNotes = strings.ReplaceAll(strings.Trim(clientUpdate.AdditionalNotes, "\r\n"), "\r\n", "\n")

		// Save the updated client.
		if err := db.SaveClient(client); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		log.Infof("Updated client information successfully => %v", client.Name)
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Updated client successfully"})
	}
}

// SetClientStatus handler enables/disables a client.
func SetClientStatus(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req setClientStatusRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Bad post data"})
		}

		if _, err := xid.FromString(req.ID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid client ID"})
		}

		clientData, err := db.GetClientByID(req.ID, model.QRCodeSettings{Enabled: false})
		if err != nil {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{Success: false, Message: err.Error()})
		}

		client := *clientData.Client
		client.Enabled = req.Status
		if err := db.SaveClient(client); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		log.Infof("Changed client %s enabled status to %v", client.ID, req.Status)
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Changed client status successfully"})
	}
}

// DownloadClient handler streams the client configuration for download.
func DownloadClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		clientID := c.QueryParam("clientid")
		if clientID == "" {
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{Success: false, Message: "Missing clientid parameter"})
		}

		if _, err := xid.FromString(clientID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid client ID"})
		}

		clientData, err := db.GetClientByID(clientID, model.QRCodeSettings{Enabled: false})
		if err != nil {
			log.Errorf("Cannot generate client config for id %s: %v", clientID, err)
			return c.JSON(http.StatusNotFound, jsonHTTPResponse{Success: false, Message: "Client not found"})
		}

		server, err := db.GetServer()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		globalSettings, err := db.GetGlobalSettings()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		config := util.BuildClientConfig(*clientData.Client, server, globalSettings)
		reader := strings.NewReader(config)
		c.Response().Header().Set(echo.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%s.conf", clientData.Client.Email))
		return c.Stream(http.StatusOK, "text/conf", reader)
	}
}

// RemoveClient handler deletes a WireGuard client.
func RemoveClient(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var client model.Client
		if err := c.Bind(&client); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Invalid client data"})
		}

		if _, err := xid.FromString(client.ID); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Please provide a valid client ID"})
		}

		if err := db.DeleteClient(client.ID); err != nil {
			log.Error("Cannot delete wireguard client: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot delete client from database"})
		}
		log.Infof("Removed wireguard client: %v", client.ID)
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Client removed"})
	}
}

// WireGuardServer handler renders the WireGuard server page.
func WireGuardServer(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot get server config: ", err)
		}
		return c.Render(http.StatusOK, "server.html", map[string]interface{}{
			"baseData":        model.BaseData{Active: "wg-server", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"serverInterface": server.Interface,
			"serverKeyPair":   server.KeyPair,
		})
	}
}

// WireGuardServerInterfaces handler updates server interface settings.
func WireGuardServerInterfaces(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var serverInterface model.ServerInterface
		if err := c.Bind(&serverInterface); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Invalid interface data"})
		}
		if !util.ValidateServerAddresses(serverInterface.Addresses) {
			log.Warnf("Invalid server interface addresses input: %v", serverInterface.Addresses)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Interface IP address must be in CIDR format"})
		}
		serverInterface.UpdatedAt = time.Now().UTC()
		if err := db.SaveServerInterface(serverInterface); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: err.Error()})
		}
		log.Infof("Updated wireguard server interfaces settings: %v", serverInterface.Addresses)
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Updated interface addresses successfully"})
	}
}

// WireGuardServerKeyPair handler generates a new WireGuard key pair.
func WireGuardServerKeyPair(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Error("Cannot generate wireguard key pair: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot generate WireGuard key pair"})
		}
		serverKeyPair := model.ServerKeypair{
			PrivateKey: key.String(),
			PublicKey:  key.PublicKey().String(),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := db.SaveServerKeyPair(serverKeyPair); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot generate WireGuard key pair"})
		}
		log.Infof("Updated wireguard server key pair: %v", serverKeyPair)
		return c.JSON(http.StatusOK, serverKeyPair)
	}
}

// GlobalSettings handler renders the global settings page.
func GlobalSettings(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		globalSettings, err := db.GetGlobalSettings()
		if err != nil {
			log.Error("Cannot get global settings: ", err)
		}
		return c.Render(http.StatusOK, "global_settings.html", map[string]interface{}{
			"baseData":       model.BaseData{Active: "global-settings", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"globalSettings": globalSettings,
		})
	}
}

// Status renders the HTML page for VPN status.
func Status(db store.IStore) echo.HandlerFunc {
	// code that renders the effective "status.html" with the default variables
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "status.html", map[string]interface{}{
			"baseData": model.BaseData{Active: "status", CurrentUser: currentUser(c), Admin: isAdmin(c)},
			"devices":  nil,
		})
	}
}

// APIStatus returns the current WireGuard status as JSON.
// This handler is intended to be polled via AJAX to update the VPN status table dynamically.
func APIStatus(db store.IStore) echo.HandlerFunc {
	// Define the view model structures.
	type PeerVM struct {
		Name              string        `json:"name"`
		Email             string        `json:"email"`
		PublicKey         string        `json:"public_key"`
		ReceivedBytes     int64         `json:"received_bytes"`
		TransmitBytes     int64         `json:"transmit_bytes"`
		LastHandshakeTime time.Time     `json:"last_handshake_time"`
		LastHandshakeRel  time.Duration `json:"last_handshake_rel"`
		Connected         bool          `json:"connected"`
		AllocatedIP       string        `json:"allocated_ip"`
		Endpoint          string        `json:"endpoint,omitempty"`
	}
	type DeviceVM struct {
		Name  string   `json:"name"`
		Peers []PeerVM `json:"peers"`
	}

	return func(c echo.Context) error {
		// Create a new WireGuard client.
		wgClient, err := wgctrl.New()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}
		// Retrieve the list of WireGuard clients.
		devices, err := wgClient.Devices()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}
		// Prepare the device view model.
		var devicesVM []DeviceVM
		if len(devices) > 0 {
			// Create a map of clients keyed by public key.
			clients, err := db.GetClients(false)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]interface{}{
					"error": err.Error(),
				})
			}
			clientMap := make(map[string]*model.Client)
			for i := range clients {
				if clients[i].Client != nil {
					clientMap[clients[i].Client.PublicKey] = clients[i].Client
				}
			}
			// Helper map for sorting based on connection status.
			conv := map[bool]int{true: 1, false: 0}

			for _, dev := range devices {
				devVm := DeviceVM{
					Name: dev.Name,
				}
				// Process each peer on the device.
				for _, peer := range dev.Peers {
					var allocatedIPs string
					// Concatenate all allowed IPs (as strings) separated by line breaks.
					for _, ip := range peer.AllowedIPs {
						if allocatedIPs != "" {
							allocatedIPs += "</br>"
						}
						allocatedIPs += ip.String()
					}

					pVm := PeerVM{
						PublicKey:         peer.PublicKey.String(),
						ReceivedBytes:     peer.ReceiveBytes,
						TransmitBytes:     peer.TransmitBytes,
						LastHandshakeTime: peer.LastHandshakeTime,
						LastHandshakeRel:  time.Since(peer.LastHandshakeTime),
						AllocatedIP:       allocatedIPs,
					}
					// Mark as connected if the last handshake was less than 3 minutes ago.
					pVm.Connected = pVm.LastHandshakeRel.Minutes() < 3.0
					// If the user is an admin, add the endpoint information.
					if isAdmin(c) {
						pVm.Endpoint = peer.Endpoint.String()
					}
					// If we have additional client info, use it.
					if client, ok := clientMap[pVm.PublicKey]; ok {
						pVm.Name = client.Name
						pVm.Email = client.Email
					}
					devVm.Peers = append(devVm.Peers, pVm)
				}

				// Sort peers alphabetically and by connection status.
				sort.SliceStable(devVm.Peers, func(i, j int) bool {
					return devVm.Peers[i].Name < devVm.Peers[j].Name
				})
				sort.SliceStable(devVm.Peers, func(i, j int) bool {
					return conv[devVm.Peers[i].Connected] > conv[devVm.Peers[j].Connected]
				})
				devicesVM = append(devicesVM, devVm)
			}
		}

		// Return the final client-devices status as JSON.
		return c.JSON(http.StatusOK, map[string]interface{}{
			"devices": devicesVM,
		})
	}
}

// GlobalSettingSubmit handler updates the global settings.
func GlobalSettingSubmit(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		var globalSettings model.GlobalSetting
		if err := c.Bind(&globalSettings); err != nil {
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Invalid global settings data"})
		}
		if !util.ValidateIPAndSearchDomainAddressList(globalSettings.DNSServers) {
			log.Warnf("Invalid DNS server list input: %v", globalSettings.DNSServers)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: "Invalid DNS server address"})
		}
		globalSettings.UpdatedAt = time.Now().UTC()
		if err := db.SaveGlobalSettings(globalSettings); err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot update global settings"})
		}
		log.Infof("Updated global settings: %v", globalSettings)
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Updated global settings successfully"})
	}
}

// MachineIPAddresses handler returns local and public interface IP addresses.
func MachineIPAddresses() echo.HandlerFunc {
	return func(c echo.Context) error {
		interfaceList, err := util.GetInterfaceIPs()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot get machine ip addresses"})
		}
		publicInterface, err := util.GetPublicIP()
		if err != nil {
			log.Warn("Cannot get machine public ip address: ", err)
		} else {
			interfaceList = append([]model.Interface{publicInterface}, interfaceList...)
		}
		return c.JSON(http.StatusOK, interfaceList)
	}
}

// GetOrderedSubnetRanges handler returns the ordered list of subnet ranges.
func GetOrderedSubnetRanges() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.JSON(http.StatusOK, util.SubnetRangesOrder)
	}
}

// SuggestIPAllocation handler returns a list of suggested IP addresses.
func SuggestIPAllocation(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot fetch server config: ", err)
			return c.JSON(http.StatusBadRequest, jsonHTTPResponse{Success: false, Message: err.Error()})
		}

		allocatedIPs, err := util.GetAllocatedIPs("")
		if err != nil {
			log.Error("Cannot suggest ip allocation: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				Success: false,
				Message: "Cannot suggest ip allocation: failed to get list of allocated ip addresses",
			})
		}

		sr := c.QueryParam("sr")
		searchCIDRList := make([]string, 0)
		found := false

		if util.SubnetRanges[sr] != nil {
			for _, cidr := range util.SubnetRanges[sr] {
				searchCIDRList = append(searchCIDRList, cidr.String())
			}
		} else {
			searchCIDRList = append(searchCIDRList, server.Interface.Addresses...)
		}

		ipSet := make(map[string]struct{})
		for _, cidr := range searchCIDRList {
			ip, err := util.GetAvailableIP(cidr, allocatedIPs, server.Interface.Addresses)
			if err != nil {
				log.Error("Failed to get available ip from CIDR: ", err)
				continue
			}
			found = true
			if strings.Contains(ip, ":") {
				ipSet[fmt.Sprintf("%s/128", ip)] = struct{}{}
			} else {
				ipSet[fmt.Sprintf("%s/32", ip)] = struct{}{}
			}
		}
		if !found {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{
				Success: false,
				Message: "Cannot suggest ip allocation: failed to get available ip. Try a different subnet or deallocate some ips.",
			})
		}
		suggestedIPs := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			suggestedIPs = append(suggestedIPs, ip)
		}
		return c.JSON(http.StatusOK, suggestedIPs)
	}
}

// ApplyServerConfig handler writes the config file and restarts the WireGuard server.
func ApplyServerConfig(db store.IStore, tmplDir fs.FS) echo.HandlerFunc {
	return func(c echo.Context) error {
		server, err := db.GetServer()
		if err != nil {
			log.Error("Cannot get server config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot get server config"})
		}
		clients, err := db.GetClients(false)
		if err != nil {
			log.Error("Cannot get client config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot get client config"})
		}
		users, err := db.GetUsers()
		if err != nil {
			log.Error("Cannot get users config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot get users config"})
		}
		settings, err := db.GetGlobalSettings()
		if err != nil {
			log.Error("Cannot get global settings: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: "Cannot get global settings"})
		}

		if err := util.WriteWireGuardServerConfig(tmplDir, server, clients, users, settings); err != nil {
			log.Error("Cannot apply server config: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: fmt.Sprintf("Cannot apply server config: %v", err)})
		}
		if err := util.UpdateHashes(db); err != nil {
			log.Error("Cannot update hashes: ", err)
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{Success: false, Message: fmt.Sprintf("Cannot update hashes: %v", err)})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Applied server config successfully"})
	}
}

// GetHashesChanges handler returns if database hashes have changed.
func GetHashesChanges(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		changed := util.HashesChanged(db)
		if changed {
			return c.JSON(http.StatusOK, jsonHTTPResponse{Success: true, Message: "Hashes changed"})
		}
		return c.JSON(http.StatusOK, jsonHTTPResponse{Success: false, Message: "Hashes not changed"})
	}
}
