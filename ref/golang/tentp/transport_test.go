//
// transport_test.go: Transport layer tests.
//

package tentp

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/nmathewson/tentp-draft/ref/golang/tentp/auth"
	"github.com/nmathewson/tentp-draft/ref/golang/tentp/enc"
)

type loopbackConn struct {
	txBuf  *bytes.Buffer
	rxBuf  *bytes.Buffer
	closed *bool
}

func (c *loopbackConn) Read(b []byte) (n int, err error) {
	if c.rxBuf.Len() > 0 {
		return c.rxBuf.Read(b)
	}
	if *c.closed {
		return 0, syscall.EBADFD
	}
	return 0, nil
}

func (c *loopbackConn) Write(b []byte) (n int, err error) {
	if *c.closed {
		return 0, syscall.EBADFD
	}
	return c.txBuf.Write(b)
}

func (c *loopbackConn) Close() error {
	if *c.closed {
		return syscall.EBADFD
	}
	*c.closed = true
	return nil
}

func (c *loopbackConn) LocalAddr() net.Addr {
	return nil
}

func (c *loopbackConn) RemoteAddr() net.Addr {
	return nil
}

func (c *loopbackConn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (c *loopbackConn) SetReadDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (c *loopbackConn) SetWriteDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func newLoopbackConn() (net.Conn, net.Conn) {
	b1 := &bytes.Buffer{}
	b2 := &bytes.Buffer{}
	closed := false

	return &loopbackConn{b1, b2, &closed}, &loopbackConn{b2, b1, &closed}
}

func TestIntegration(t *testing.T) {
	const keySize = 40 // Ew. :( (auth.ChaCha20.KeySize())

	// Generate random keys.
	var k1, k2 [keySize]byte
	if _, err := rand.Read(k1[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(k2[:]); err != nil {
		t.Fatal(err)
	}

	// Wrap a pair of memory backed "connections".
	c1, c2 := newLoopbackConn()
	tc1, err := WrapConn(c1, auth.NewPoly1305, enc.NewChaCha20, k1[:], k2[:])
	if err != nil {
		t.Fatal(err)
	}
	tc2, err := WrapConn(c2, auth.NewPoly1305, enc.NewChaCha20, k2[:], k1[:])
	if err != nil {
		t.Fatal(err)
	}

	// Send/receive data 0 < payloadLen <= MaxPlaintextRecordLen.
	txBuf := make([]byte, MaxPlaintextRecordLen)
	rxBuf1 := make([]byte, MaxPlaintextRecordLen)
	rxBuf2 := make([]byte, MaxPlaintextRecordLen)
	for i := range txBuf {
		txBuf[i] = byte(i)
	}
	for i := 1; i <= MaxPlaintextRecordLen; i++ {
		n, err := tc1.Write(txBuf[:i])
		if err != nil || n != i {
			t.Fatalf("tc1.Write(txBuf): %d, %s", n, err)
		}
		n, err = tc2.Write(txBuf[:i])
		if err != nil || n != i {
			t.Fatalf("tc2.Write(txBuf): %d, %s", n, err)
		}

		n, err = tc2.Read(rxBuf2)
		if err != nil || n != i {
			t.Fatalf("tc2.Read(rxBuf2): %d, %s", n, err)
		}
		n, err = tc1.Read(rxBuf1)
		if err != nil || n != i {
			t.Fatalf("tc1.Read(rxBuf1): %d, %s", n, err)
		}

		if !bytes.Equal(txBuf[:i], rxBuf1[:i]) {
			t.Fatalf("txBuf[:%d] != rxBuf1[:%d]", i, i)
		}
		if !bytes.Equal(txBuf[:i], rxBuf2[:i]) {
			t.Fatalf("txBuf[:%d] != rxBuf2[:%d]", i, i)
		}
	}

	// Test authenticated close.
	if err = tc1.Close(); err != nil {
		t.Fatal(err)
	}
	var tmp [MaxPlaintextRecordLen]byte
	n, err := tc2.Read(tmp[:])
	if n != 0 || err != io.EOF {
		t.Fatalf("tc2.Read(tmp) (Closed): %d, %s", n, err)
	}
}
