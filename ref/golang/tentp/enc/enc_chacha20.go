//
// enc_chacha20.go: ChaCha20 ENC.
//

package enc

import (
	"crypto/cipher"
	"errors"

	"github.com/codahale/chacha20"
)

// ChaCha20 implements the TENTP ENC algorithm via the ChaCha20 stream cipher.
//
// WARNING: A pure Go ChaCha20 implementation is used, so performance is not
// going to be spectacular (~75 MiB/s on a i5-4250U).
type ChaCha20 struct {
	c cipher.Stream
}

func (s *ChaCha20) XORKeyStream(dst, src []byte) {
	if s.c == nil {
		panic("chacha20: key not set")
	}
	s.c.XORKeyStream(dst, src)
}

func (s *ChaCha20) KeyStream(n int) []byte {
	if s.c == nil {
		panic("chacha20: key not set")
	}
	b := make([]byte, n)
	s.c.XORKeyStream(b, b)
	return b
}

func (s *ChaCha20) Key(key []byte) error {
	var err error
	if len(key) != chacha20.KeySize+chacha20.NonceSize {
		return errors.New("chacha20: invalid key size")
	}
	if s.c, err = chacha20.New(key[:chacha20.KeySize], key[chacha20.KeySize:]); err != nil {
		return err
	}
	return nil
}

func (s *ChaCha20) KeySize() int {
	return chacha20.KeySize + chacha20.NonceSize
}

func NewChaCha20() Enc {
	return &ChaCha20{}
}

var _ Enc = (*ChaCha20)(nil)
