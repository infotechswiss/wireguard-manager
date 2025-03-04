package util

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"math/rand"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/chmike/domain"
	"github.com/swissmakers/wireguard-manager/model"
	"github.com/swissmakers/wireguard-manager/store"
	"golang.org/x/mod/sumdb/dirhash"

	externalip "github.com/glendc/go-external-ip"
	"github.com/labstack/gommon/log"
	"github.com/sdomino/scribble"
)

//
// Client Configuration Building
//

// BuildClientConfig creates the WireGuard client configuration as a string.
func BuildClientConfig(client model.Client, server model.Server, setting model.GlobalSetting) string {
	// [Interface] section
	clientAddress := fmt.Sprintf("Address = %s\n", strings.Join(client.AllocatedIPs, ","))
	clientPrivateKey := fmt.Sprintf("PrivateKey = %s\n", client.PrivateKey)
	clientDNS := ""
	if client.UseServerDNS {
		clientDNS = fmt.Sprintf("DNS = %s\n", strings.Join(setting.DNSServers, ","))
	}
	clientMTU := ""
	if setting.MTU > 0 {
		clientMTU = fmt.Sprintf("MTU = %d\n", setting.MTU)
	}

	// [Peer] section
	peerPublicKey := fmt.Sprintf("PublicKey = %s\n", server.KeyPair.PublicKey)
	peerPresharedKey := ""
	if client.PresharedKey != "" {
		peerPresharedKey = fmt.Sprintf("PresharedKey = %s\n", client.PresharedKey)
	}
	peerAllowedIPs := fmt.Sprintf("AllowedIPs = %s\n", strings.Join(client.AllowedIPs, ","))

	desiredHost := setting.EndpointAddress
	desiredPort := server.Interface.ListenPort
	if strings.Contains(desiredHost, ":") {
		split := strings.Split(desiredHost, ":")
		desiredHost = split[0]
		if n, err := strconv.Atoi(split[1]); err == nil {
			desiredPort = n
		} else {
			log.Error("Endpoint appears to be incorrectly formatted: ", err)
		}
	}
	peerEndpoint := fmt.Sprintf("Endpoint = %s:%d\n", desiredHost, desiredPort)
	peerPersistentKeepalive := ""
	if setting.PersistentKeepalive > 0 {
		peerPersistentKeepalive = fmt.Sprintf("PersistentKeepalive = %d\n", setting.PersistentKeepalive)
	}

	strConfig := "[Interface]\n" +
		clientAddress +
		clientPrivateKey +
		clientDNS +
		clientMTU +
		"\n[Peer]\n" +
		peerPublicKey +
		peerPresharedKey +
		peerAllowedIPs +
		peerEndpoint +
		peerPersistentKeepalive

	return strConfig
}

// ClientDefaultsFromEnv returns default client creation values from environment variables or sane defaults.
func ClientDefaultsFromEnv() model.ClientDefaults {
	return model.ClientDefaults{
		AllowedIPs:          LookupEnvOrStrings(DefaultClientAllowedIpsEnvVar, []string{"0.0.0.0/0"}),
		ExtraAllowedIPs:     LookupEnvOrStrings(DefaultClientExtraAllowedIpsEnvVar, []string{}),
		UseServerDNS:        LookupEnvOrBool(DefaultClientUseServerDNSEnvVar, true),
		EnableAfterCreation: LookupEnvOrBool(DefaultClientEnableAfterCreationEnvVar, true),
	}
}

//
// CIDR and IP Validation
//

// ContainsCIDR returns true if ipnet1 completely contains ipnet2.
func ContainsCIDR(ipnet1, ipnet2 *net.IPNet) bool {
	ones1, _ := ipnet1.Mask.Size()
	ones2, _ := ipnet2.Mask.Size()
	return ones1 <= ones2 && ipnet1.Contains(ipnet2.IP)
}

// ValidateCIDR returns true if the given CIDR is valid.
func ValidateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// ValidateCIDRList validates a slice of CIDRs.
// If allowEmpty is true, empty strings are allowed.
func ValidateCIDRList(cidrs []string, allowEmpty bool) bool {
	for _, cidr := range cidrs {
		if allowEmpty && len(cidr) == 0 {
			continue
		}
		if !ValidateCIDR(cidr) {
			return false
		}
	}
	return true
}

// ValidateAllowedIPs validates a list of allowed IP addresses in CIDR format.
func ValidateAllowedIPs(cidrs []string) bool {
	return ValidateCIDRList(cidrs, false)
}

// ValidateExtraAllowedIPs validates extra allowed IPs, allowing empty strings.
func ValidateExtraAllowedIPs(cidrs []string) bool {
	return ValidateCIDRList(cidrs, true)
}

// ValidateServerAddresses validates server interface addresses in CIDR format.
func ValidateServerAddresses(cidrs []string) bool {
	return ValidateCIDRList(cidrs, false)
}

// ValidateIPAddress checks whether a given string is a valid IPv4 or IPv6 address.
func ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ValidateDomainName checks whether a domain name is valid.
func ValidateDomainName(name string) bool {
	return domain.Check(name) == nil
}

// ValidateIPAndSearchDomainAddressList validates a list of IP addresses followed by search domains.
func ValidateIPAndSearchDomainAddressList(entries []string) bool {
	var ipFound, domainFound bool
	for _, entry := range entries {
		if ValidateIPAddress(entry) && !domainFound {
			ipFound = true
			continue
		}
		if ValidateDomainName(entry) && ipFound {
			domainFound = true
			continue
		}
		return false
	}
	return true
}

//
// Local and Public IP Retrieval
//

// GetInterfaceIPs returns the list of local interface IP addresses (IPv4 only).
func GetInterfaceIPs() ([]model.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var interfaceList []model.Interface
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			interfaceList = append(interfaceList, model.Interface{
				Name:      iface.Name,
				IPAddress: ip.String(),
			})
		}
	}
	return interfaceList, nil
}

// GetPublicIP returns the public IP address of the machine using an external consensus.
func GetPublicIP() (model.Interface, error) {
	cfg := externalip.ConsensusConfig{Timeout: 5 * time.Second}
	consensus := externalip.NewConsensus(&cfg, nil)
	consensus.AddVoter(externalip.NewHTTPSource("https://checkip.amazonaws.com/"), 1)
	consensus.AddVoter(externalip.NewHTTPSource("http://whatismyip.akamai.com"), 1)
	consensus.AddVoter(externalip.NewHTTPSource("https://ifconfig.top"), 1)

	publicInterface := model.Interface{Name: "Public Address"}
	ip, err := consensus.ExternalIP()
	if err != nil {
		publicInterface.IPAddress = "N/A"
	} else {
		publicInterface.IPAddress = ip.String()
	}
	return publicInterface, nil
}

//
// IP Extraction and Allocation
//

// GetIPFromCIDR extracts the IP portion from a CIDR notation.
func GetIPFromCIDR(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// GetAllocatedIPs returns all IP addresses allocated to clients and the server.
// The ignoreClientID parameter can be used to exclude a specific client.
func GetAllocatedIPs(ignoreClientID string) ([]string, error) {
	var allocatedIPs []string

	// Initialize the scribble DB.
	db, err := scribble.New("./db", nil)
	if err != nil {
		return nil, err
	}

	// Read server interface addresses.
	var serverInterface model.ServerInterface
	if err := db.Read("server", "interfaces", &serverInterface); err != nil {
		return nil, err
	}
	for _, cidr := range serverInterface.Addresses {
		ip, err := GetIPFromCIDR(cidr)
		if err != nil {
			return nil, err
		}
		allocatedIPs = append(allocatedIPs, ip)
	}

	// Read clients.
	records, err := db.ReadAll("clients")
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		var client model.Client
		if err := json.Unmarshal(record, &client); err != nil {
			return nil, err
		}
		if client.ID != ignoreClientID {
			for _, cidr := range client.AllocatedIPs {
				ip, err := GetIPFromCIDR(cidr)
				if err != nil {
					return nil, err
				}
				allocatedIPs = append(allocatedIPs, ip)
			}
		}
	}

	return allocatedIPs, nil
}

// inc increments an IP address by one.
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetBroadcastIP computes the broadcast address of a given network.
func GetBroadcastIP(n *net.IPNet) net.IP {
	broadcast := make(net.IP, len(n.IP))
	for i := range n.IP {
		broadcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return broadcast
}

// GetBroadcastAndNetworkAddrsLookup returns a map of addresses (broadcast and network addresses)
// for the given interface addresses (CIDRs).
func GetBroadcastAndNetworkAddrsLookup(interfaceAddresses []string) map[string]bool {
	list := make(map[string]bool)
	for _, ifa := range interfaceAddresses {
		_, netAddr, err := net.ParseCIDR(ifa)
		if err != nil {
			continue
		}
		list[GetBroadcastIP(netAddr).String()] = true
		list[netAddr.IP.String()] = true
	}
	return list
}

// GetAvailableIP returns an available IP from the given CIDR that is not allocated and is not a network/broadcast address.
func GetAvailableIP(cidr string, allocatedList, interfaceAddresses []string) (string, error) {
	ip, netAddr, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	unavailableIPs := GetBroadcastAndNetworkAddrsLookup(interfaceAddresses)
	for ip := ip.Mask(netAddr.Mask); netAddr.Contains(ip); inc(ip) {
		suggestedAddr := ip.String()
		available := true
		for _, allocated := range allocatedList {
			if suggestedAddr == allocated {
				available = false
				break
			}
		}
		if available && !unavailableIPs[suggestedAddr] {
			return suggestedAddr, nil
		}
	}
	return "", errors.New("no more available ip address")
}

// ValidateIPAllocation validates the client's requested IP allocation.
func ValidateIPAllocation(serverAddresses []string, ipAllocatedList []string, ipAllocationList []string) (bool, error) {
	for _, clientCIDR := range ipAllocationList {
		ip, _, _ := net.ParseCIDR(clientCIDR)
		if ip == nil {
			return false, fmt.Errorf("invalid ip allocation input %s. Must be in CIDR format", clientCIDR)
		}
		for _, allocated := range ipAllocatedList {
			if allocated == ip.String() {
				return false, fmt.Errorf("IP %s already allocated", ip)
			}
		}
		var isValid bool
		for _, serverCIDR := range serverAddresses {
			_, serverNet, _ := net.ParseCIDR(serverCIDR)
			if serverNet.Contains(ip) {
				isValid = true
				break
			}
		}
		if !isValid {
			return false, fmt.Errorf("IP %s does not belong to any network addresses of WireGuard server", ip)
		}
	}
	return true, nil
}

//
// Subnet Ranges and Client Data Helpers
//

// findSubnetRangeForIP finds the subnet range for a given CIDR.
// It uses a cache (IPToSubnetRange) and the global SubnetRanges and SubnetRangesOrder.
func findSubnetRangeForIP(cidr string) (uint16, error) {
	// Parse the provided CIDR.
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	ipStr := ip.String()

	// Check the cache first using a read lock.
	ipToSubnetRangeMutex.RLock()
	if sr, ok := IPToSubnetRange[ipStr]; ok {
		ipToSubnetRangeMutex.RUnlock()
		return sr, nil
	}
	ipToSubnetRangeMutex.RUnlock()

	// Iterate over the global SubnetRangesOrder to compute the subnet range index.
	for index, srName := range SubnetRangesOrder {
		cidrList, ok := SubnetRanges[srName]
		if !ok {
			continue
		}
		// For each CIDR in the current subnet range, check if it contains the IP.
		for _, ipnet := range cidrList {
			if ipnet.Contains(ip) {
				// Lock for writing and store the computed index in the cache.
				ipToSubnetRangeMutex.Lock()
				IPToSubnetRange[ipStr] = uint16(index)
				ipToSubnetRangeMutex.Unlock()
				return uint16(index), nil
			}
		}
	}
	return 0, fmt.Errorf("subnet range not found for IP %s", ipStr)
}

// FillClientSubnetRange appends the subnet range names to the client data.
func FillClientSubnetRange(client model.ClientData) model.ClientData {
	cl := *client.Client
	for _, ip := range cl.AllocatedIPs {
		if sr, err := findSubnetRangeForIP(ip); err == nil {
			cl.SubnetRanges = append(cl.SubnetRanges, SubnetRangesOrder[sr])
		}
	}
	return model.ClientData{
		Client: &cl,
		QRCode: client.QRCode,
	}
}

// ValidateAndFixSubnetRanges checks and removes non-valid CIDRs from the global SubnetRanges.
func ValidateAndFixSubnetRanges(db store.IStore) error {
	if len(SubnetRangesOrder) == 0 {
		return nil
	}
	server, err := db.GetServer()
	if err != nil {
		return err
	}
	var serverSubnets []*net.IPNet
	for _, addr := range server.Interface.Addresses {
		addr = strings.TrimSpace(addr)
		_, netAddr, err := net.ParseCIDR(addr)
		if err != nil {
			return err
		}
		serverSubnets = append(serverSubnets, netAddr)
	}
	for _, rng := range SubnetRangesOrder {
		cidrs := SubnetRanges[rng]
		if len(cidrs) > 0 {
			newCIDRs := make([]*net.IPNet, 0)
			for _, cidr := range cidrs {
				valid := false
				for _, serverSubnet := range serverSubnets {
					if ContainsCIDR(serverSubnet, cidr) {
						valid = true
						break
					}
				}
				if valid {
					newCIDRs = append(newCIDRs, cidr)
				} else {
					log.Warnf("[%v] CIDR is outside of all server subnets: %v. Removed.", rng, cidr)
				}
			}
			if len(newCIDRs) > 0 {
				SubnetRanges[rng] = newCIDRs
			} else {
				delete(SubnetRanges, rng)
				log.Warnf("[%v] No valid CIDRs in this subnet range. Removed.", rng)
			}
		}
	}
	return nil
}

// GetSubnetRangesString returns a formatted string representing active subnet ranges.
func GetSubnetRangesString() string {
	if len(SubnetRangesOrder) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, rng := range SubnetRangesOrder {
		cidrs := SubnetRanges[rng]
		if len(cidrs) > 0 {
			sb.WriteString(rng)
			sb.WriteString(":[")
			for i, cidr := range cidrs {
				if i > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(cidr.String())
			}
			sb.WriteString("]  ")
		}
	}
	return strings.TrimSpace(sb.String())
}

//
// WireGuard Server Configuration File
//

// WriteWireGuardServerConfig writes the WireGuard server configuration (wg.conf) using a template.
// If WgConfTemplate is set, it is used; otherwise, a default embedded template is read.
func WriteWireGuardServerConfig(tmplDir fs.FS, serverConfig model.Server, clientDataList []model.ClientData, usersList []model.User, globalSettings model.GlobalSetting) error {
	var tmplWireGuardConf string
	if len(WgConfTemplate) > 0 {
		data, err := os.ReadFile(WgConfTemplate)
		if err != nil {
			return err
		}
		tmplWireGuardConf = string(data)
	} else {
		fileContent, err := StringFromEmbedFile(tmplDir, "wg.conf")
		if err != nil {
			return err
		}
		tmplWireGuardConf = fileContent
	}
	tmplParsed, err := template.New("wg_config").Parse(tmplWireGuardConf)
	if err != nil {
		return err
	}
	f, err := os.Create(globalSettings.ConfigFilePath)
	if err != nil {
		return err
	}
	defer f.Close()
	config := map[string]interface{}{
		"serverConfig":   serverConfig,
		"clientDataList": clientDataList,
		"globalSettings": globalSettings,
		"usersList":      usersList,
	}
	return tmplParsed.Execute(f, config)
}

//
// Environment Variable Helpers
//

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func LookupEnvOrBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		if parsed, err := strconv.ParseBool(val); err == nil {
			return parsed
		} else {
			fmt.Fprintf(os.Stderr, "LookupEnvOrBool[%s]: %v\n", key, err)
		}
	}
	return defaultVal
}

func LookupEnvOrInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		} else {
			fmt.Fprintf(os.Stderr, "LookupEnvOrInt[%s]: %v\n", key, err)
		}
	}
	return defaultVal
}

func LookupEnvOrStrings(key string, defaultVal []string) []string {
	if val, ok := os.LookupEnv(key); ok {
		return strings.Split(val, ",")
	}
	return defaultVal
}

// LookupEnvOrFile reads the content of a file whose path is stored in the environment variable.
func LookupEnvOrFile(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		f, err := os.Open(val)
		if err != nil {
			return defaultVal
		}
		defer f.Close()
		var content strings.Builder
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			content.WriteString(scanner.Text())
		}
		return content.String()
	}
	return defaultVal
}

// StringFromEmbedFile reads a file from an embedded filesystem and returns its content as a string.
func StringFromEmbedFile(efs fs.FS, filename string) (string, error) {
	file, err := efs.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ParseLogLevel converts a log level string to log.Lvl.
func ParseLogLevel(lvl string) (log.Lvl, error) {
	switch strings.ToLower(lvl) {
	case "debug":
		return log.DEBUG, nil
	case "info":
		return log.INFO, nil
	case "warn":
		return log.WARN, nil
	case "error":
		return log.ERROR, nil
	case "off":
		return log.OFF, nil
	default:
		return log.DEBUG, fmt.Errorf("not a valid log level: %s", lvl)
	}
}

//
// Hashing and Database Helpers
//

// GetCurrentHash returns current hashes for clients and server configuration.
func GetCurrentHash(db store.IStore) (string, string) {
	hashClients, _ := dirhash.HashDir(path.Join(db.GetPath(), "clients"), "prefix", dirhash.Hash1)
	files := append([]string(nil), "prefix/global_settings.json", "prefix/interfaces.json", "prefix/keypair.json")
	osOpen := func(name string) (io.ReadCloser, error) {
		return os.Open(filepath.Join(path.Join(db.GetPath(), "server"), strings.TrimPrefix(name, "prefix")))
	}
	hashServer, _ := dirhash.Hash1(files, osOpen)
	return hashClients, hashServer
}

// HashesChanged returns true if the current hashes differ from those stored in the database.
func HashesChanged(db store.IStore) bool {
	old, _ := db.GetHashes()
	newClient, newServer := GetCurrentHash(db)
	return old.Client != newClient || old.Server != newServer
}

// UpdateHashes updates the stored hashes in the database.
func UpdateHashes(db store.IStore) error {
	var clientServerHashes model.ClientServerHashes
	clientServerHashes.Client, clientServerHashes.Server = GetCurrentHash(db)
	return db.SaveHashes(clientServerHashes)
}

//
// Miscellaneous Helpers
//

// RandomString returns a random string of the given length.
func RandomString(length int) string {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// ManagePerms sets file permissions to 0600.
func ManagePerms(path string) error {
	return os.Chmod(path, 0600)
}

// GetDBUserCRC32 returns a CRC32 checksum of the given user.
// This is used for session verification.
func GetDBUserCRC32(dbuser model.User) uint32 {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(dbuser); err != nil {
		panic("model.User is gob-incompatible, session verification is impossible")
	}
	return crc32.ChecksumIEEE(buf.Bytes())
}

// ConcatMultipleSlices concatenates multiple byte slices.
func ConcatMultipleSlices(slices ...[]byte) []byte {
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	result := make([]byte, totalLen)
	var i int
	for _, s := range slices {
		i += copy(result[i:], s)
	}
	return result
}

// GetCookiePath returns the cookie path based on BasePath.
func GetCookiePath() string {
	if BasePath == "" {
		return "/"
	}
	return BasePath
}

// GetPersistedSessionSecret retrieves a stable session secret from the JSON DB.
// It first checks if the SESSION_SECRET environment variable is set. If not,
// it attempts to read the secret from the "config" collection (key "session_secret")
// in the JSON DB (located in "./db"). If no secret is stored, it generates a new one,
// saves it to the JSON DB, and returns it.
func GetPersistedSessionSecret() string {
	// First, check if the environment variable is set.
	if secret := LookupEnvOrString("SESSION_SECRET", ""); secret != "" {
		// Trim any accidental whitespace.
		return strings.TrimSpace(secret)
	}

	// Open the Scribble DB at "./db".
	db, err := scribble.New("./db", nil)
	if err != nil {
		log.Errorf("Error opening json db for session secret: %v", err)
		// Fallback: generate a random secret.
		return RandomString(32)
	}

	// Attempt to read the session secret from the "config" collection with key "session_secret".
	var storedSecret string
	err = db.Read("config", "session_secret", &storedSecret)
	if err == nil && strings.TrimSpace(storedSecret) != "" {
		return strings.TrimSpace(storedSecret)
	}

	// No valid secret was found, so generate a new one.
	newSecret := RandomString(32)
	// Save the new secret in the JSON DB.
	err = db.Write("config", "session_secret", newSecret)
	if err != nil {
		log.Errorf("Error saving session secret to json db: %v", err)
		// Even if saving fails, return the generated secret.
	}
	return newSecret
}
