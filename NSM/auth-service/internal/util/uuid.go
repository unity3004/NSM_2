package util

import (
	"crypto/rand"
	"fmt"
)

// NewUUID generates an RFC 4122 version-4 UUID using crypto/rand — enough
// to give every entity.* row a globally unique ID without pulling in a
// third-party UUID library for something this small.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the OS's entropy source is broken —
		// not a condition any caller can meaningfully recover from.
		panic("util: crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0F) | 0x40 // version 4
	b[8] = (b[8] & 0x3F) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
