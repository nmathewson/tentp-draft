//
// auth_poly1305.go: Poly1305 AUTH.
//

package auth

import (
	"bytes"

	"golang.org/x/crypto/poly1305"
)

const (
	authKeyLen = 32
	authLen    = poly1305.TagSize
)

// Poly1305 implements the TENTP AUTH algorithm via the Poly1305 MAC.
//
// WARNING: To work around the golang.org/x/crypto implementation not
// supporting incremental processing, a full copy of the summed data is
// created, and then processed all at once when Sum() is called.
type Poly1305 struct {
	keyValid bool
	key      [authKeyLen]byte
	buf      bytes.Buffer
}

func (p *Poly1305) Write(b []byte) (n int, err error) {
	if !p.keyValid {
		// Why yes, this does not return an error, to be consistent with how
		// hash.Hash behaves.
		panic(ErrKeyNotSet)
	}
	return p.buf.Write(b)
}

func (p *Poly1305) Sum(b []byte) []byte {
	if !p.keyValid {
		panic(ErrKeyNotSet)
	}
	var tag [authLen]byte
	poly1305.Sum(&tag, p.buf.Bytes(), &p.key)
	b = append(b, tag[:]...)
	return b
}

func (p *Poly1305) Key(key []byte) error {
	if len(key) != authKeyLen {
		return ErrInvalidKeyLength
	}
	p.Clear()
	copy(p.key[:], key)
	p.keyValid = true
	return nil
}

func (p *Poly1305) Clear() {
	p.keyValid = false
	for i := range p.key {
		p.key[i] = 0
	}
	p.buf.Reset()
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
