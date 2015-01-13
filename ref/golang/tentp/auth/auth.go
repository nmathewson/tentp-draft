//
// auth.go: TENTP AUTH interface.
//

// Package auth is the base interface for the AUTH algorithm for the TENTP
// transport layer.  It is similar to the runtime library's hash.Hash
// interface, with a few minor additions to better suit how transport protocols
// work.
package auth

import (
	"crypto/subtle"
	"errors"
	"io"
)

// Auth is a interface that provides a TENTP Transport Layer AUTH instance.
type Auth interface {
	io.Writer

	// Sum appends the current hash to b and returns the resulting slice.
	// It does not change the underlying hash state.
	Sum(b []byte) []byte

	// Key resets the Auth routine to it's initial state and changes the key.
	Key(key []byte) error

	// Clear() destroys the internal state.
	Clear()

	// Size returns the number of bytes Sum will return.
	Size() int

	// KeySize returns the number of bytes expected as the key.
	KeySize() int
}

// Equal returns true when the contents of the two slices are equal, using a
// constant time comparison.
func Equal(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// ErrKeyNotSet is the error returned when a given Auth instance has not been
// initialized.
var ErrKeyNotSet = errors.New("auth: key not set")

// ErrInvalidKeyLength is the error returned when a invalid key is provided.
var ErrInvalidKeyLength = errors.New("auth: invalid key length")
