//
// enc_aes256.go: CTR-AES256 ENC.
//

package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AES implements the TENTP ENC algorithm via CTR-AES256.
type AES256 struct {
	c cipher.Stream
}

func (s *AES256) XORKeyStream(dst, src []byte) {
	if s.c == nil {
		panic("aes256: key not set")
	}
	s.c.XORKeyStream(dst, src)
}

func (s *AES256) KeyStream(n int) []byte {
	if s.c == nil {
		panic("aes256: key not set")
	}
	b := make([]byte, n)
	s.c.XORKeyStream(b, b)
	return b
}

func (s *AES256) Key(key []byte) error {
	var err error
	if len(key) != 32+aes.BlockSize {
		return errors.New("aes256: invalid key size")
	}
	blk, err := aes.NewCipher(key[:32])
	if err != nil {
		return err
	}
	s.c = cipher.NewCTR(blk, key[32:])

	return nil
}

func (s *AES256) KeySize() int {
	return 32 + aes.BlockSize
}

func NewAES256() Enc {
	return &AES256{}
}
