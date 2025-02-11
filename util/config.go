package util

import (
	"net"
	"strings"

	"github.com/labstack/gommon/log"
)

// Global runtime configuration variables.
var (
	DisableLogin       bool
	Proxy              bool
	BindAddress        string
	SmtpHostname       string
	SmtpPort           int
	SmtpUsername       string
	SmtpPassword       string
	SmtpNoTLSCheck     bool
	SmtpEncryption     string
	SmtpAuthType       string
	SmtpHelo           string
	SendgridApiKey     string
	EmailFrom          string
	EmailFromName      string
	SessionSecret      [64]byte
	SessionMaxDuration int64
	WgConfTemplate     string
	BasePath           string
	SubnetRanges       map[string][]*net.IPNet // Mapping of range name to slice of *net.IPNet
	SubnetRangesOrder  []string                // Order of subnet range names
)

// Default values and environment variable names.
const (
	DefaultUsername                        = "admin"
	DefaultPassword                        = "swissmakers"
	DefaultIsAdmin                         = true
	DefaultServerAddress                   = "10.8.0.0/24"
	DefaultServerPort                      = 8443
	DefaultDNS                             = "8.8.8.8"
	DefaultMTU                             = 1450
	DefaultPersistentKeepalive             = 15
	DefaultFirewallMark                    = "0xca6c" // e.g. 8443
	DefaultTable                           = "auto"
	DefaultConfigFilePath                  = "/etc/wireguard/wg0.conf"
	UsernameEnvVar                         = "WGM_USERNAME"
	PasswordEnvVar                         = "WGM_PASSWORD"
	PasswordFileEnvVar                     = "WGM_PASSWORD_FILE"
	PasswordHashEnvVar                     = "WGM_PASSWORD_HASH"
	PasswordHashFileEnvVar                 = "WGM_PASSWORD_HASH_FILE"
	FaviconFilePathEnvVar                  = "WGM_FAVICON_FILE_PATH"
	EndpointAddressEnvVar                  = "WGM_ENDPOINT_ADDRESS"
	DNSEnvVar                              = "WGM_DNS"
	MTUEnvVar                              = "WGM_MTU"
	PersistentKeepaliveEnvVar              = "WGM_PERSISTENT_KEEPALIVE"
	FirewallMarkEnvVar                     = "WGM_FIREWALL_MARK"
	TableEnvVar                            = "WGM_TABLE"
	ConfigFilePathEnvVar                   = "WGM_CONFIG_FILE_PATH"
	LogLevel                               = "WGM_LOG_LEVEL"
	ServerAddressesEnvVar                  = "WGM_SERVER_INTERFACE_ADDRESSES"
	ServerListenPortEnvVar                 = "WGM_SERVER_LISTEN_PORT"
	ServerPostUpScriptEnvVar               = "WGM_SERVER_POST_UP_SCRIPT"
	ServerPostDownScriptEnvVar             = "WGM_SERVER_POST_DOWN_SCRIPT"
	DefaultClientAllowedIpsEnvVar          = "WGM_DEFAULT_CLIENT_ALLOWED_IPS"
	DefaultClientExtraAllowedIpsEnvVar     = "WGM_DEFAULT_CLIENT_EXTRA_ALLOWED_IPS"
	DefaultClientUseServerDNSEnvVar        = "WGM_DEFAULT_CLIENT_USE_SERVER_DNS"
	DefaultClientEnableAfterCreationEnvVar = "WGM_DEFAULT_CLIENT_ENABLE_AFTER_CREATION"
)

// ParseBasePath ensures that the base path starts with a slash and does not end with one.
func ParseBasePath(basePath string) string {
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	return strings.TrimSuffix(basePath, "/")
}

// ParseSubnetRanges parses a string containing subnet ranges into a map of subnet ranges.
// The expected format is:
//
//	rangeName:CIDR1,CIDR2;rangeName2:CIDR3,CIDR4
//
// It returns a map from the range name to a slice of *net.IPNet and populates SubnetRangesOrder.
func ParseSubnetRanges(subnetRangesStr string) map[string][]*net.IPNet {
	subnetRanges := make(map[string][]*net.IPNet)
	// Reset the global order.
	SubnetRangesOrder = []string{}

	if subnetRangesStr == "" {
		return subnetRanges
	}

	// Clean the input string.
	subnetRangesStr = strings.TrimSpace(subnetRangesStr)
	subnetRangesStr = strings.Trim(subnetRangesStr, ";:,")
	ranges := strings.Split(subnetRangesStr, ";")

	// Use a set to track duplicate CIDRs.
	cidrSet := make(map[string]bool)

	for _, rng := range ranges {
		rng = strings.TrimSpace(rng)
		parts := strings.Split(rng, ":")
		if len(parts) != 2 {
			log.Warnf("Unable to parse subnet range: %v. Skipped.", rng)
			continue
		}
		rangeName := strings.TrimSpace(parts[0])
		subnetRanges[rangeName] = []*net.IPNet{}

		// Split the CIDRs by comma.
		cidrs := strings.Split(parts[1], ",")
		for _, cidr := range cidrs {
			cidr = strings.TrimSpace(cidr)
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Warnf("[%v] Unable to parse CIDR: %v. Skipped.", rangeName, cidr)
				continue
			}
			if cidrSet[ipnet.String()] {
				log.Warnf("[%v] CIDR already exists: %v. Skipped.", rangeName, ipnet.String())
				continue
			}
			cidrSet[ipnet.String()] = true
			subnetRanges[rangeName] = append(subnetRanges[rangeName], ipnet)
		}

		// Remove the range if no valid CIDRs were found.
		if len(subnetRanges[rangeName]) == 0 {
			delete(subnetRanges, rangeName)
		} else {
			SubnetRangesOrder = append(SubnetRangesOrder, rangeName)
		}
	}
	return subnetRanges
}
