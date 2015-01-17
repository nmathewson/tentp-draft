//
// auth_poly1305.go: Poly1305 AUTH.
//

package auth

import (
	"github.com/yawning/poly1305"
)

const (
	authKeyLen = poly1305.KeySize
	authLen    = poly1305.Size
)

// Poly1305 implements the TENTP AUTH algorithm via the Poly1305 MAC.
type Poly1305 struct {
	poly1305.Poly1305
	keyValid bool
}

func (p *Poly1305) Write(b []byte) (n int, err error) {
	if !p.keyValid {
		// Why yes, this does not return an error, to be consistent with how
		// hash.Hash behaves.
		panic(ErrKeyNotSet)
	}
	return p.Poly1305.Write(b)
}

func (p *Poly1305) Sum(b []byte) []byte {
	if !p.keyValid {
		panic(ErrKeyNotSet)
	}
	return p.Poly1305.Sum(b)
}

func (p *Poly1305) Key(key []byte) error {
	if len(key) != authKeyLen {
		return ErrInvalidKeyLength
	}
	p.Init(key)
	p.keyValid = true
	return nil
}

func (p *Poly1305) Clear() {
	p.keyValid = false
	p.Poly1305.Clear()
}

func (p *Poly1305) Size() int {
	return authLen
}

func (p *Poly1305) KeySize() int {
	return authKeyLen
}

func NewPoly1305() Auth {
	return &Poly1305{}
}

var _ Auth = (*Poly1305)(nil)
