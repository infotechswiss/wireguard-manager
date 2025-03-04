package main

import (
	"crypto/sha512"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/swissmakers/wireguard-manager/emailer"
	"github.com/swissmakers/wireguard-manager/handler"
	"github.com/swissmakers/wireguard-manager/router"
	"github.com/swissmakers/wireguard-manager/store"
	"github.com/swissmakers/wireguard-manager/store/jsondb"
	"github.com/swissmakers/wireguard-manager/util"
)

var (
	// App version information.
	appVersion = "stable"
	gitCommit  = "N/A"
	gitRef     = "N/A"
	buildTime  = time.Now().UTC().Format("01-02-2006 15:04:05")

	// Configuration variables with defaults.
	flagDisableLogin   = false
	flagProxy          = false
	flagBindAddress    = "0.0.0.0:5000"
	flagSmtpHostname   = "127.0.0.1"
	flagSmtpPort       = 25
	flagSmtpUsername   string
	flagSmtpPassword   string
	flagSmtpAuthType   = "NONE"
	flagSmtpNoTLSCheck = false
	flagSmtpEncryption = "STARTTLS"
	flagSmtpHelo       = "localhost"
	flagSendgridApiKey string
	flagEmailFrom      string
	flagEmailFromName  = "WireGuard Manager"
	// IMPORTANT: Instead of generating a new random secret on each run,
	// we now persist the secret in our JSON DB if no SESSION_SECRET is provided.
	flagSessionSecret      = util.GetPersistedSessionSecret()
	flagSessionMaxDuration = 90
	flagWgConfTemplate     string
	flagBasePath           string
	flagSubnetRanges       string
)

const (
	defaultEmailSubject = "Your wireguard configuration"
	defaultEmailContent = `Hi,</br>
<p>In this email you can find your personal configuration for our wireguard server.</p>
<p>Best</p>
`
)

//go:embed templates/*
var embeddedTemplates embed.FS

//go:embed assets/*
var embeddedAssets embed.FS

func init() {
	// Bind command-line flags and environment variables.
	flag.BoolVar(&flagDisableLogin, "disable-login", util.LookupEnvOrBool("DISABLE_LOGIN", flagDisableLogin), "Disable authentication on the app. This is potentially dangerous.")
	flag.BoolVar(&flagProxy, "proxy", util.LookupEnvOrBool("PROXY", flagProxy), "Behind a proxy. Use X-FORWARDED-FOR for failed login logging")
	flag.StringVar(&flagBindAddress, "bind-address", util.LookupEnvOrString("BIND_ADDRESS", flagBindAddress), "Address:Port to which the app will be bound.")
	flag.StringVar(&flagSmtpHostname, "smtp-hostname", util.LookupEnvOrString("SMTP_HOSTNAME", flagSmtpHostname), "SMTP Hostname")
	flag.IntVar(&flagSmtpPort, "smtp-port", util.LookupEnvOrInt("SMTP_PORT", flagSmtpPort), "SMTP Port")
	flag.StringVar(&flagSmtpHelo, "smtp-helo", util.LookupEnvOrString("SMTP_HELO", flagSmtpHelo), "SMTP HELO Hostname")
	flag.StringVar(&flagSmtpUsername, "smtp-username", util.LookupEnvOrString("SMTP_USERNAME", flagSmtpUsername), "SMTP Username")
	flag.BoolVar(&flagSmtpNoTLSCheck, "smtp-no-tls-check", util.LookupEnvOrBool("SMTP_NO_TLS_CHECK", flagSmtpNoTLSCheck), "Disable TLS verification for SMTP. This is potentially dangerous.")
	flag.StringVar(&flagSmtpEncryption, "smtp-encryption", util.LookupEnvOrString("SMTP_ENCRYPTION", flagSmtpEncryption), "SMTP Encryption: NONE, SSL, SSLTLS, TLS or STARTTLS (by default)")
	flag.StringVar(&flagSmtpAuthType, "smtp-auth-type", util.LookupEnvOrString("SMTP_AUTH_TYPE", flagSmtpAuthType), "SMTP Auth Type: PLAIN, LOGIN or NONE.")
	flag.StringVar(&flagEmailFrom, "email-from", util.LookupEnvOrString("EMAIL_FROM_ADDRESS", flagEmailFrom), "'From' email address.")
	flag.StringVar(&flagEmailFromName, "email-from-name", util.LookupEnvOrString("EMAIL_FROM_NAME", flagEmailFromName), "'From' email name.")
	flag.StringVar(&flagWgConfTemplate, "wg-conf-template", util.LookupEnvOrString("WG_CONF_TEMPLATE", flagWgConfTemplate), "Path to custom wg.conf template.")
	flag.StringVar(&flagBasePath, "base-path", util.LookupEnvOrString("BASE_PATH", flagBasePath), "The base path of the URL")
	flag.StringVar(&flagSubnetRanges, "subnet-ranges", util.LookupEnvOrString("SUBNET_RANGES", flagSubnetRanges), "IP ranges to choose from when assigning an IP for a client.")
	flag.IntVar(&flagSessionMaxDuration, "session-max-duration", util.LookupEnvOrInt("SESSION_MAX_DURATION", flagSessionMaxDuration), "Max time in days a remembered session is refreshed and valid.")

	// Handle SMTP password, Sendgrid API key and session secret.
	var (
		smtpPasswordLookup   = util.LookupEnvOrString("SMTP_PASSWORD", flagSmtpPassword)
		sendgridApiKeyLookup = util.LookupEnvOrString("SENDGRID_API_KEY", flagSendgridApiKey)
		sessionSecretLookup  = util.LookupEnvOrString("SESSION_SECRET", flagSessionSecret)
	)

	if smtpPasswordLookup != "" {
		flag.StringVar(&flagSmtpPassword, "smtp-password", smtpPasswordLookup, "SMTP Password")
	} else {
		flag.StringVar(&flagSmtpPassword, "smtp-password", util.LookupEnvOrFile("SMTP_PASSWORD_FILE", flagSmtpPassword), "SMTP Password File")
	}

	if sendgridApiKeyLookup != "" {
		flag.StringVar(&flagSendgridApiKey, "sendgrid-api-key", sendgridApiKeyLookup, "Your sendgrid api key.")
	} else {
		flag.StringVar(&flagSendgridApiKey, "sendgrid-api-key", util.LookupEnvOrFile("SENDGRID_API_KEY_FILE", flagSendgridApiKey), "File containing your sendgrid api key.")
	}

	// Use the persisted session secret as default.
	if sessionSecretLookup != "" {
		flag.StringVar(&flagSessionSecret, "session-secret", sessionSecretLookup, "The key used to encrypt session cookies.")
	} else {
		flag.StringVar(&flagSessionSecret, "session-secret", util.LookupEnvOrFile("SESSION_SECRET_FILE", flagSessionSecret), "File containing the key used to encrypt session cookies.")
	}

	flag.Parse()

	// Update runtime config in util package.
	util.DisableLogin = flagDisableLogin
	util.Proxy = flagProxy
	util.BindAddress = flagBindAddress
	util.SmtpHostname = flagSmtpHostname
	util.SmtpPort = flagSmtpPort
	util.SmtpHelo = flagSmtpHelo
	util.SmtpUsername = flagSmtpUsername
	util.SmtpPassword = flagSmtpPassword
	util.SmtpAuthType = flagSmtpAuthType
	util.SmtpNoTLSCheck = flagSmtpNoTLSCheck
	util.SmtpEncryption = flagSmtpEncryption
	util.SendgridApiKey = flagSendgridApiKey
	util.EmailFrom = flagEmailFrom
	util.EmailFromName = flagEmailFromName
	// Use a stable session secret.
	util.SessionSecret = sha512.Sum512([]byte(flagSessionSecret))
	// DEBUG: Log the session secret hash for verification (remove in production)
	log.Debugf("Using session secret (SHA512 hash): %x", util.SessionSecret)
	util.SessionMaxDuration = int64(flagSessionMaxDuration) * 86_400 // store in seconds
	util.WgConfTemplate = flagWgConfTemplate
	util.BasePath = util.ParseBasePath(flagBasePath)
	util.SubnetRanges = util.ParseSubnetRanges(flagSubnetRanges)

	// Set log level.
	lvl, _ := util.ParseLogLevel(util.LookupEnvOrString(util.LogLevel, "INFO"))
	log.SetLevel(lvl)

	// Print app information if log level is INFO or lower.
	if lvl <= log.INFO {
		fmt.Println("WireGuard Manager")
		fmt.Println("App Version\t:", appVersion)
		fmt.Println("Git Commit\t:", gitCommit)
		fmt.Println("Git Ref\t\t:", gitRef)
		fmt.Println("Build Time\t:", buildTime)
		fmt.Println("Git Repo\t:", "https://github.com/swissmakers/wireguard-manager")
		fmt.Println("Authentication\t:", !util.DisableLogin)
		fmt.Println("Bind address\t:", util.BindAddress)
		fmt.Println("Email from\t:", util.EmailFrom)
		fmt.Println("Email from name\t:", util.EmailFromName)
		fmt.Println("Custom wg.conf\t:", util.WgConfTemplate)
		fmt.Println("Base path\t:", util.BasePath+"/")
		fmt.Println("Subnet ranges\t:", util.GetSubnetRangesString())
	}
}

func main() {
	// Initialize the JSON DB store.
	db, err := jsondb.New("./db")
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	if err := db.Init(); err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

	// Extra app data for templates.
	extraData := map[string]interface{}{
		"appVersion":    appVersion,
		"gitCommit":     gitCommit,
		"basePath":      util.BasePath,
		"loginDisabled": flagDisableLogin,
	}

	// Strip the "templates/" prefix from the embedded templates directory.
	tmplDir, err := fs.Sub(embeddedTemplates, "templates")
	if err != nil {
		log.Fatalf("Error processing templates: %v", err)
	}

	// Create the WireGuard server configuration if it doesn't exist.
	initServerConfig(db, tmplDir)

	// Validate and fix subnet ranges.
	if err := util.ValidateAndFixSubnetRanges(db); err != nil {
		log.Fatalf("Invalid subnet ranges: %v", err)
	}
	if lvl, _ := util.ParseLogLevel(util.LookupEnvOrString(util.LogLevel, "INFO")); lvl <= log.INFO {
		fmt.Println("Valid subnet ranges:", util.GetSubnetRangesString())
	}

	// Initialize the Echo router using our optimized router.New.
	app := router.New(tmplDir, extraData, util.SessionSecret)

	// Additional middleware: Clear invalid session cookies from both response and request.
	app.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, err := session.Get("session", c); err != nil {
				log.Debugf("session.Get failed: %v", err)
				// Clear invalid cookie in response.
				cookie := &http.Cookie{
					Name:     "session_token",
					Value:    "",
					Path:     util.GetCookiePath(),
					MaxAge:   -1,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				}
				c.SetCookie(cookie)
				// Also remove the invalid cookie from the request header.
				c.Request().Header.Del("Cookie")
			}
			return next(c)
		}
	})

	// Register routes. (Note: The order of middleware matters.)
	app.GET(util.BasePath, handler.WireGuardClients(db), handler.ValidSession, handler.RefreshSession)
	if !util.DisableLogin {
		app.GET(util.BasePath+"/login", handler.LoginPage())
		app.POST(util.BasePath+"/login", handler.Login(db), handler.ContentTypeJson)
		app.GET(util.BasePath+"/logout", handler.Logout(), handler.ValidSession)
		app.GET(util.BasePath+"/profile", handler.LoadProfile(), handler.ValidSession, handler.RefreshSession)
		app.GET(util.BasePath+"/users-settings", handler.UsersSettings(), handler.ValidSession, handler.RefreshSession, handler.NeedsAdmin)
		app.POST(util.BasePath+"/update-user", handler.UpdateUser(db), handler.ValidSession, handler.ContentTypeJson)
		app.POST(util.BasePath+"/create-user", handler.CreateUser(db), handler.ValidSession, handler.ContentTypeJson, handler.NeedsAdmin)
		app.POST(util.BasePath+"/remove-user", handler.RemoveUser(db), handler.ValidSession, handler.ContentTypeJson, handler.NeedsAdmin)
		app.GET(util.BasePath+"/get-users", handler.GetUsers(db), handler.ValidSession, handler.NeedsAdmin)
		app.GET(util.BasePath+"/api/user/:username", handler.GetUser(db), handler.ValidSession)
	}

	// Initialize the email sender.
	var sendmail emailer.Emailer
	if util.SendgridApiKey != "" {
		sendmail = emailer.NewSendgridApiMail(util.SendgridApiKey, util.EmailFromName, util.EmailFrom)
	} else {
		sendmail = emailer.NewSmtpMail(util.SmtpHostname, util.SmtpPort, util.SmtpUsername, util.SmtpPassword,
			util.SmtpHelo, util.SmtpNoTLSCheck, util.SmtpAuthType, util.EmailFromName, util.EmailFrom, util.SmtpEncryption)
	}

	// Additional API and page routes.
	app.GET(util.BasePath+"/test-hash", handler.GetHashesChanges(db), handler.ValidSession)
	app.GET(util.BasePath+"/_health", handler.Health())
	app.GET(util.BasePath+"/favicon", handler.Favicon())
	app.POST(util.BasePath+"/new-client", handler.NewClient(db), handler.ValidSession, handler.ContentTypeJson)
	app.POST(util.BasePath+"/update-client", handler.UpdateClient(db), handler.ValidSession, handler.ContentTypeJson)
	app.POST(util.BasePath+"/email-client", handler.EmailClient(db, sendmail, defaultEmailSubject, defaultEmailContent),
		handler.ValidSession, handler.ContentTypeJson)
	app.POST(util.BasePath+"/client/set-status", handler.SetClientStatus(db), handler.ValidSession, handler.ContentTypeJson)
	app.POST(util.BasePath+"/remove-client", handler.RemoveClient(db), handler.ValidSession, handler.ContentTypeJson)
	app.GET(util.BasePath+"/download", handler.DownloadClient(db), handler.ValidSession)
	app.GET(util.BasePath+"/wg-server", handler.WireGuardServer(db), handler.ValidSession, handler.RefreshSession, handler.NeedsAdmin)
	app.POST(util.BasePath+"/wg-server/interfaces", handler.WireGuardServerInterfaces(db),
		handler.ValidSession, handler.ContentTypeJson, handler.NeedsAdmin)
	app.POST(util.BasePath+"/wg-server/keypair", handler.WireGuardServerKeyPair(db),
		handler.ValidSession, handler.ContentTypeJson, handler.NeedsAdmin)
	app.GET(util.BasePath+"/global-settings", handler.GlobalSettings(db),
		handler.ValidSession, handler.RefreshSession, handler.NeedsAdmin)
	app.POST(util.BasePath+"/global-settings", handler.GlobalSettingSubmit(db),
		handler.ValidSession, handler.ContentTypeJson, handler.NeedsAdmin)
	app.GET(util.BasePath+"/status", handler.Status(db), handler.ValidSession, handler.RefreshSession)
	app.GET(util.BasePath+"/api/clients", handler.GetClients(db), handler.ValidSession)
	app.GET(util.BasePath+"/api/client/:id", handler.GetClient(db), handler.ValidSession)
	app.GET(util.BasePath+"/api/machine-ips", handler.MachineIPAddresses(), handler.ValidSession)
	app.GET(util.BasePath+"/api/connection-status", handler.APIStatus(db), handler.ValidSession)
	app.GET(util.BasePath+"/api/subnet-ranges", handler.GetOrderedSubnetRanges(), handler.ValidSession)
	app.GET(util.BasePath+"/api/suggest-client-ips", handler.SuggestIPAllocation(db), handler.ValidSession)
	app.POST(util.BasePath+"/api/apply-wg-config", handler.ApplyServerConfig(db, tmplDir),
		handler.ValidSession, handler.ContentTypeJson)

	// Serve static files from the embedded assets.
	assetsDir, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		log.Fatalf("Error processing assets: %v", err)
	}
	assetHandler := http.FileServer(http.FS(assetsDir))
	app.GET(util.BasePath+"/static/*", echo.WrapHandler(http.StripPrefix(util.BasePath+"/static/", assetHandler)))

	// Listen on the appropriate socket.
	if strings.HasPrefix(util.BindAddress, "unix://") {
		// For Unix domain sockets.
		if err := syscall.Unlink(util.BindAddress[6:]); err != nil {
			app.Logger.Fatalf("Cannot unlink unix socket: %v", err)
		}
		l, err := net.Listen("unix", util.BindAddress[6:])
		if err != nil {
			app.Logger.Fatalf("Cannot create unix socket: %v", err)
		}
		app.Listener = l
		app.Logger.Fatal(app.Start(""))
	} else {
		// For TCP sockets.
		app.Logger.Fatal(app.Start(util.BindAddress))
	}
}

// initServerConfig creates the WireGuard config file if it doesn't exist.
func initServerConfig(db store.IStore, tmplDir fs.FS) {
	settings, err := db.GetGlobalSettings()
	if err != nil {
		log.Fatalf("Cannot get global settings: %v", err)
	}

	if _, err := os.Stat(settings.ConfigFilePath); err == nil {
		// Config file exists; do not overwrite.
		return
	}

	server, err := db.GetServer()
	if err != nil {
		log.Fatalf("Cannot get server config: %v", err)
	}

	clients, err := db.GetClients(false)
	if err != nil {
		log.Fatalf("Cannot get client config: %v", err)
	}

	users, err := db.GetUsers()
	if err != nil {
		log.Fatalf("Cannot get user config: %v", err)
	}

	if err := util.WriteWireGuardServerConfig(tmplDir, server, clients, users, settings); err != nil {
		log.Fatalf("Cannot create server config: %v", err)
	}
}
