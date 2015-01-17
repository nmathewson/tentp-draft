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

type transportSuite struct {
	name    string
	keySize int
	authFn  func() auth.Auth
	encFn   func() enc.Enc
}

var (
	suiteChaCha20 = &transportSuite{
		"poly1305/ChaCha20",
		32 + 8,
		auth.NewPoly1305,
		enc.NewChaCha20,
	}

	suiteAES256 = &transportSuite{
		"poly1305/CTR-AES256",
		32 + 16,
		auth.NewPoly1305,
		enc.NewAES256,
	}

	allSuites = []*transportSuite{
		suiteChaCha20,
		suiteAES256,
	}
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

func setupIntegration(tb testing.TB, suite *transportSuite) (net.Conn, net.Conn) {
	// Generate random keys.
	k1 := make([]byte, suite.keySize)
	if _, err := rand.Read(k1[:]); err != nil {
		tb.Fatal(err)
	}
	k2 := make([]byte, suite.keySize)
	if _, err := rand.Read(k2[:]); err != nil {
		tb.Fatal(err)
	}

	// Wrap a pair of memory backed "connections".
	c1, c2 := newLoopbackConn()
	tc1, err := WrapConn(c1, suite.authFn, suite.encFn, k1[:], k2[:])
	if err != nil {
		tb.Fatal(err)
	}
	tc2, err := WrapConn(c2, suite.authFn, suite.encFn, k2[:], k1[:])
	if err != nil {
		tb.Fatal(err)
	}

	return tc1, tc2
}

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	for _, suite := range allSuites {
		tc1, tc2 := setupIntegration(t, suite)

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
		if err := tc1.Close(); err != nil {
			t.Fatal(err)
		}
		var tmp [MaxPlaintextRecordLen]byte
		n, err := tc2.Read(tmp[:])
		if n != 0 || err != io.EOF {
			t.Fatalf("tc2.Read(tmp) (Closed): %d, %s", n, err)
		}
	}
}

func doBenchmark(b *testing.B, suite *transportSuite, sz int, isRead bool) {
	tc1, tc2 := setupIntegration(b, suite)
	txBuf := make([]byte, sz)
	rxBuf := make([]byte, sz)
	b.SetBytes(int64(sz))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if isRead {
			b.StopTimer()
		} else {
			b.StartTimer()
		}

		n, err := tc1.Write(txBuf)
		if err != nil || n != sz {
			b.Fatalf("tc1.Write(txBuf): %d, %s", n, err)
		}

		if isRead {
			b.StartTimer()
		} else {
			b.StopTimer()
		}

		n, err = tc2.Read(rxBuf)
		if err != nil || n != sz {
			b.Fatalf("tc2.Read(rxBuf): %d, %s", n, err)
		}
	}
}

func BenchmarkChaCha20Write64(b *testing.B) {
	doBenchmark(b, suiteChaCha20, 64, false)
}

func BenchmarkChaCha20Read64(b *testing.B) {
	doBenchmark(b, suiteChaCha20, 64, true)
}

func BenchmarkChaCha20Write512(b *testing.B) {
	doBenchmark(b, suiteChaCha20, 512, false)
}

func BenchmarkChaCha20Read512(b *testing.B) {
	doBenchmark(b, suiteChaCha20, 512, true)
}

func BenchmarkChaCha20Write16383(b *testing.B) {
	doBenchmark(b, suiteChaCha20, 16383, false)
}

func BenchmarkChaCha20Read16383(b *testing.B) {
	doBenchmark(b, suiteChaCha20, 16383, true)
}

func BenchmarkAES256Write64(b *testing.B) {
	doBenchmark(b, suiteAES256, 64, false)
}

func BenchmarkAES256Read64(b *testing.B) {
	doBenchmark(b, suiteAES256, 64, true)
}

func BenchmarkAES256Write512(b *testing.B) {
	doBenchmark(b, suiteAES256, 512, false)
}

func BenchmarkAES256Read512(b *testing.B) {
	doBenchmark(b, suiteAES256, 512, true)
}

func BenchmarkAES256Write16383(b *testing.B) {
	doBenchmark(b, suiteAES256, 16383, false)
}

func BenchmarkAES256Read16383(b *testing.B) {
	doBenchmark(b, suiteAES256, 16383, true)
}
