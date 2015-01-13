//
// enc.go : TENTP ENC interface.
//

// Package enc is the base interface for the ENC algorithm for the TENTP
// transport layer.  It extends the runtime library's cipher.Stream
// interface, with certain required additons.
package enc

import (
	"crypto/cipher"
)

// Enc is a interface that provides a TENTP Transport Layer ENC instance.
type Enc interface {
	cipher.Stream

	// KeyStream returns n bytes from the cipher's key stream.
	KeyStream(n int) []byte

	// Key re-initializes the Enc instance with a given key.
	Key(key []byte) error

	// KeySize() returns the number of bytes expected as the key.
	KeySize() int
}
