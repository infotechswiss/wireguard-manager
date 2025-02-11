package util

import "sync"

// IPToSubnetRange caches a mapping from an IP address (as a string) to a subnet range index.
// Note: This global map is not thread-safe by default. Use ipToSubnetRangeMutex for concurrent access.
var IPToSubnetRange = make(map[string]uint16)

// DBUsersToCRC32 caches a mapping from a username to its corresponding CRC32 hash value.
// Note: This global map is not thread-safe by default. Use dbUsersToCRC32Mutex for concurrent access.
var DBUsersToCRC32 = make(map[string]uint32)

// Mutexes to protect concurrent access to the caches.
// Use ipToSubnetRangeMutex when reading from or writing to IPToSubnetRange,
// and use dbUsersToCRC32Mutex for DBUsersToCRC32.
var (
	ipToSubnetRangeMutex sync.RWMutex
	//dbUsersToCRC32Mutex  sync.RWMutex
)
