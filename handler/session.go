package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/swissmakers/wireguard-manager/util"
)

// ValidSession is middleware that checks for a valid session.
// If the session is invalid, it redirects the user to the login page.
func ValidSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !isValidSession(c) {
			// If the request is a GET, append the current URL as a query parameter "next"
			if c.Request().Method == http.MethodGet {
				return c.Redirect(http.StatusTemporaryRedirect,
					fmt.Sprintf("%s/login?next=%s", util.BasePath, c.Request().URL.String()))
			}
			return c.Redirect(http.StatusTemporaryRedirect, util.BasePath+"/login?next="+util.BasePath)
		}
		return next(c)
	}
}

// RefreshSession middleware refreshes a "remember me" session.
// This should be used after ValidSession has verified the session.
func RefreshSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		doRefreshSession(c)
		return next(c)
	}
}

// NeedsAdmin middleware ensures that only admin users proceed.
func NeedsAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !isAdmin(c) {
			return c.Redirect(http.StatusTemporaryRedirect, util.BasePath+"/")
		}
		return next(c)
	}
}

// isValidSession checks whether the session is valid.
func isValidSession(c echo.Context) bool {
	// If login is disabled, always return true.
	if util.DisableLogin {
		return true
	}

	// Retrieve session; if an error occurs, consider the session invalid.
	sess, err := session.Get("session", c)
	if err != nil {
		return false
	}

	// Check for a valid session token in both session and cookie.
	cookie, err := c.Cookie("session_token")
	if err != nil || sess.Values["session_token"] != cookie.Value {
		return false
	}

	// Check time bounds.
	createdAt := getCreatedAt(sess)
	updatedAt := getUpdatedAt(sess)
	maxAge := getMaxAge(sess)
	if maxAge == 0 {
		// Default temporary session duration (24h) when not set.
		maxAge = 86400
	}
	expiration := updatedAt + int64(maxAge)
	now := time.Now().UTC().Unix()
	if updatedAt > now || expiration < now || createdAt+util.SessionMaxDuration < now {
		return false
	}

	// Check if user still exists and has not changed.
	username := fmt.Sprintf("%s", sess.Values["username"])
	userHash := getUserHash(sess)
	if uHash, ok := util.DBUsersToCRC32[username]; !ok || userHash != uHash {
		return false
	}

	return true
}

// doRefreshSession refreshes the session data if the session is eligible.
// The session must already be valid before calling this function.
func doRefreshSession(c echo.Context) {
	if util.DisableLogin {
		return
	}

	sess, err := session.Get("session", c)
	if err != nil {
		// Cannot retrieve session; nothing to do.
		return
	}

	maxAge := getMaxAge(sess)
	if maxAge <= 0 {
		return
	}

	oldCookie, err := c.Cookie("session_token")
	if err != nil || sess.Values["session_token"] != oldCookie.Value {
		return
	}

	// Determine if a refresh is due.
	createdAt := getCreatedAt(sess)
	updatedAt := getUpdatedAt(sess)
	expiration := updatedAt + int64(maxAge)
	now := time.Now().UTC().Unix()
	// Only refresh if at least 24h have passed since last update
	// and the session has not yet reached its maximum duration.
	if updatedAt > now || expiration < now || now-updatedAt < 86_400 || createdAt+util.SessionMaxDuration < now {
		return
	}

	cookiePath := util.GetCookiePath()

	// Update the session timestamp.
	sess.Values["updated_at"] = now
	sess.Options = &sessions.Options{
		Path:     cookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		// Log error if needed.
		return
	}

	// Reset the session cookie.
	cookie := &http.Cookie{
		Name:     "session_token",
		Path:     cookiePath,
		Value:    oldCookie.Value,
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	c.SetCookie(cookie)
}

// getMaxAge returns the session's maximum age (in seconds).
func getMaxAge(sess *sessions.Session) int {
	if util.DisableLogin {
		return 0
	}
	maxAgeVal := sess.Values["max_age"]
	switch v := maxAgeVal.(type) {
	case int:
		return v
	case int64:
		return int(v)
	default:
		return 0
	}
}

// getCreatedAt returns the timestamp when the session was created.
func getCreatedAt(sess *sessions.Session) int64 {
	if util.DisableLogin {
		return 0
	}
	createdAtVal := sess.Values["created_at"]
	switch v := createdAtVal.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	default:
		return 0
	}
}

// getUpdatedAt returns the timestamp of the last session update.
func getUpdatedAt(sess *sessions.Session) int64 {
	if util.DisableLogin {
		return 0
	}
	updatedAtVal := sess.Values["updated_at"]
	switch v := updatedAtVal.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	default:
		return 0
	}
}

// getUserHash returns the CRC32 hash of the user at the time of login.
func getUserHash(sess *sessions.Session) uint32 {
	if util.DisableLogin {
		return 0
	}
	userHashVal := sess.Values["user_hash"]
	switch v := userHashVal.(type) {
	case uint32:
		return v
	// In case the hash was stored as an int, convert it.
	case int:
		return uint32(v)
	case int64:
		return uint32(v)
	default:
		return 0
	}
}

// currentUser retrieves the username of the logged-in user.
func currentUser(c echo.Context) string {
	if util.DisableLogin {
		return ""
	}
	sess, err := session.Get("session", c)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s", sess.Values["username"])
}

// isAdmin checks whether the logged-in user is an admin.
func isAdmin(c echo.Context) bool {
	if util.DisableLogin {
		return true
	}
	sess, err := session.Get("session", c)
	if err != nil {
		return false
	}
	// Use type assertion for a boolean.
	if admin, ok := sess.Values["admin"].(bool); ok {
		return admin
	}
	return false
}

// setUser updates the session with new user information.
func setUser(c echo.Context, username string, admin bool, userCRC32 uint32) {
	sess, err := session.Get("session", c)
	if err != nil {
		return
	}
	sess.Values["username"] = username
	sess.Values["user_hash"] = userCRC32
	sess.Values["admin"] = admin
	_ = sess.Save(c.Request(), c.Response())
}

// clearSession removes the current session data and invalidates the session cookie.
func clearSession(c echo.Context) {
	sess, err := session.Get("session", c)
	if err == nil {
		sess.Values["username"] = ""
		sess.Values["user_hash"] = 0
		sess.Values["admin"] = false
		sess.Values["session_token"] = ""
		sess.Values["max_age"] = -1
		sess.Options.MaxAge = -1
		_ = sess.Save(c.Request(), c.Response())
	}

	cookiePath := util.GetCookiePath()
	cookie, err := c.Cookie("session_token")
	if err != nil {
		cookie = &http.Cookie{}
	}
	cookie.Name = "session_token"
	cookie.Path = cookiePath
	cookie.MaxAge = -1
	cookie.HttpOnly = true
	cookie.SameSite = http.SameSiteLaxMode
	c.SetCookie(cookie)
}
