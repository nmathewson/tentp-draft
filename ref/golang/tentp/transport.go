//
// transport.go: TENTP transport layer
//
// WARNING: This is based on an experimental draft version of the specification
// and SHOULD NOT BE USED.
//

// Package tentp is a implementation of TENTP, with the goal of being correct
// and easy to follow.  It is not designed for extremely high performance, and
// certain features expected of a net.Conn such as timeouts have been omitted
// as they would complicate the implementation.
//
// Note: panic() is used for invariants.
package tentp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/nmathewson/tentp-draft/ref/golang/tentp/auth"
	"github.com/nmathewson/tentp-draft/ref/golang/tentp/enc"
)

const (
	// MaxPlaintextRecordLen is the maximum plaintext contained in a record in
	// bytes.
	MaxPlaintextRecordLen = 16383

	counterLen      = 8
	recordHeaderLen = 8
)

const (
	cmdData = iota
	cmdClose
)

var (
	// ErrInvalidKeyLength is the error returned when a provided key is
	// invalid.
	ErrInvalidKeyLength = errors.New("tentp: invalid key length")

	// ErrCounterWrapped is the error returned when the send or receive counter
	// wrapped.  It is currently non-fatal (though further sends or recives
	// will be impossible), but this may change to be fatal.
	ErrCounterWrapped = errors.New("tentp: counter wrapped")

	// ErrInvalidMessageLength is the error returned when the message length is
	// invalid.
	ErrInvalidMessageLength = errors.New("tentp: invalid msg length")

	// ErrInvalidHeaderLength is the error returned when the header length is
	// invalid.
	ErrInvalidHeaderLength = errors.New("tentp: invalid header length")

	// ErrInvalidCommand is the error returned when a record containing an
	// invalid command is received.
	ErrInvalidCommand = errors.New("tentp: invalid command")

	// ErrInvalidTag is the error returned when the record authentication
	// fails.
	ErrInvalidTag = errors.New("tentp: invalid auth tag")

	// ErrNotSupported is the error returned when a call is not supported.
	ErrNotSupported = errors.New("tentp: not supported")
)

type tentpKeyState struct {
	auth       auth.Auth
	authKeyLen int
	authLen    int

	enc       enc.Enc
	encKeyLen int

	ctr uint64
	key []byte
	err error
}

func newKeyState(a auth.Auth, e enc.Enc, key []byte) (*tentpKeyState, error) {
	if len(key) != e.KeySize() {
		return nil, ErrInvalidKeyLength
	}
	s := &tentpKeyState{
		auth:       a,
		enc:        e,
		key:        make([]byte, e.KeySize()),
		authKeyLen: a.KeySize(),
		authLen:    a.Size(),
		encKeyLen:  e.KeySize(),
	}
	copy(s.key, key)
	return s, nil
}

type tentpRecordHeader struct {
	command       uint8
	length        uint16
	paddingLength uint8
	reserved      uint32
}

func (hdr *tentpRecordHeader) FromBytes(b []byte) error {
	if len(b) != recordHeaderLen {
		return ErrInvalidHeaderLength
	}
	hdr.command = b[0]
	hdr.length = binary.BigEndian.Uint16(b[1:3])
	hdr.paddingLength = b[3]
	hdr.reserved = binary.BigEndian.Uint32(b[4:]) // XXX: Ignore?
	if int(hdr.length)+int(hdr.paddingLength) > MaxPlaintextRecordLen {
		return ErrInvalidMessageLength
	}
	return nil
}

func (hdr *tentpRecordHeader) Bytes() []byte {
	b := make([]byte, recordHeaderLen)
	b[0] = hdr.command
	binary.BigEndian.PutUint16(b[1:3], hdr.length)
	b[3] = hdr.paddingLength
	binary.BigEndian.PutUint32(b[4:], hdr.reserved)
	return b
}

type tentpRecord struct {
	hdr  tentpRecordHeader
	body []byte
}

func newTentpRecord(cmd uint8, body []byte, paddingLen int) (*tentpRecord, error) {
	// Special case empty records.
	rec := &tentpRecord{}
	rec.hdr.command = cmd
	if (body == nil || len(body) == 0) && paddingLen == 0 {
		return rec, nil
	}

	// Validate the length constraints on the body/padding.
	if len(body)+paddingLen > MaxPlaintextRecordLen || paddingLen > math.MaxUint8 {
		return nil, ErrInvalidMessageLength
	}
	rec.hdr.length = uint16(len(body))
	rec.hdr.paddingLength = uint8(paddingLen)
	rec.body = make([]byte, len(body)+paddingLen)
	copy(rec.body, body)
	return rec, nil
}

type tentpConn struct {
	conn net.Conn

	recvState *tentpKeyState
	sendState *tentpKeyState

	recvBuf  bytes.Buffer
	sendLock sync.Mutex
}

func (c *tentpConn) Read(b []byte) (n int, err error) {
	for {
		// If there is buffered payload, return that.
		if c.recvBuf.Len() > 0 {
			return c.recvBuf.Read(b)
		}

		if c.recvState.err != nil {
			return 0, c.recvState.err
		}

		// Process a record off the network.
		var rec *tentpRecord
		if rec, err = c.recvRecord(); err != nil {
			c.forceClose()
			return
		}
		switch rec.hdr.command {
		case cmdData:
			c.recvBuf.Write(rec.body[:rec.hdr.length])
		case cmdClose:
			// XXX: Check that there is no payload?
			c.forceClose()
			return 0, io.EOF // ST -> GOT CLOSED
		default:
			c.forceClose()
			return 0, ErrInvalidCommand
		}
	}
}

func (c *tentpConn) Write(b []byte) (n int, err error) {
	c.sendLock.Lock()
	defer c.sendLock.Unlock()

	// HACK: While the protocol allows this, the net.Conn interface won't make
	// forward progress since it expects to actually pass data to the user.
	if len(b) == 0 {
		return 0, ErrInvalidMessageLength
	}

	// Send up to MAX_PLAINTEXT_LEN from b.
	n = len(b)
	if n > MaxPlaintextRecordLen {
		n = MaxPlaintextRecordLen
	}

	// Build the record.
	var rec *tentpRecord
	if rec, err = newTentpRecord(cmdData, b[:n], 0); err != nil {
		panic(err)
	}

	// Encrypt/transmit the record.
	if err = c.sendRecord(rec); err != nil {
		c.forceClose()
		return
	}
	return
}

func (c *tentpConn) Close() error {
	c.sendLock.Lock()
	defer c.sendLock.Unlock()

	// Graceful shutdown, send a CMD_CLOSE record then close the connection.
	rec, _ := newTentpRecord(cmdClose, nil, 0)
	c.sendRecord(rec) // Bleah, just swallow errors produced here.
	return c.forceClose()
}

func (c *tentpConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *tentpConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *tentpConn) SetDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *tentpConn) SetReadDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *tentpConn) SetWriteDeadline(t time.Time) error {
	return ErrNotSupported
}

func (c *tentpConn) recvRecord() (rec *tentpRecord, err error) {
	// Note: This assumes that none of the reads will ever be interrupted (eg:
	// via a timeout).  While it's possible to handle such things, it
	// complicates the code dramatically for a reference implementation.

	st := c.recvState // Save typing.
	rec = &tentpRecord{}

	// ST -> READING HEADER

	// Read AUTH_LEN + RECORD_HEADER_LEN bytes to obtain the header auth tag,
	// and the encrypted header.
	authHdr := make([]byte, st.authLen+recordHeaderLen)
	if _, err = io.ReadFull(c.conn, authHdr); err != nil {
		return nil, err
	}

	// Key the ENC() stream cipher used to generate the one time keys.
	if err = st.enc.Key(st.key); err != nil {
		panic(err)
	}

	// Derive tentp_record_keys.authkey1, tentp_record_keys.authkey2.
	authKey1 := st.enc.KeyStream(st.authKeyLen)
	authKey2 := st.enc.KeyStream(st.authKeyLen)

	// Serialize NRECV into network byte order.
	var nrecv [counterLen]byte
	binary.BigEndian.PutUint64(nrecv[:], st.ctr)

	// Calcuate header_auth and validate that it is correct.
	if err = st.auth.Key(authKey1); err != nil {
		panic(err)
	}
	st.auth.Write(nrecv[:])
	st.auth.Write(authHdr[st.authLen:])
	hdrAuth := st.auth.Sum(nil)
	if !auth.Equal(hdrAuth, authHdr[:st.authLen]) {
		return nil, ErrInvalidTag
	}

	// Decrypt and parse encrypted_header.
	rawHdr := authHdr[st.authLen:]
	st.enc.XORKeyStream(rawHdr, rawHdr)
	if err = rec.hdr.FromBytes(rawHdr); err != nil {
		return nil, err
	}

	// If the record has payload and/or padding...
	if rec.hdr.length > 0 || rec.hdr.paddingLength > 0 { // ST -> READING BODY
		// Read body_auth | encrypted_body.
		bLen := int(rec.hdr.length) + int(rec.hdr.paddingLength)
		authBody := make([]byte, st.authLen+bLen)
		if _, err = io.ReadFull(c.conn, authBody); err != nil {
			return nil, err
		}

		// Calculate body_auth and validate that it is correct.
		if err = st.auth.Key(authKey2); err != nil {
			panic(err)
		}
		st.auth.Write(nrecv[:])
		st.auth.Write(authBody[st.authLen:])
		bodyAuth := st.auth.Sum(nil)
		if !auth.Equal(bodyAuth, authBody[:st.authLen]) {
			return nil, ErrInvalidTag
		}

		// Decrypt encrypted_body.
		rec.body = authBody[st.authLen:]
		st.enc.XORKeyStream(rec.body, rec.body)

		// ST -> READING HEADER (Technically when the return happens...)
	}

	// Derive tentp_record_keys.next_key, and increment the counter.
	st.key = st.enc.KeyStream(st.encKeyLen)
	st.ctr++
	if st.ctr == 0 {
		// The counter wrapped, can't receive anymore records past the one
		// that was just read.  Hope it was a CMD_CLOSE.
		st.err = ErrCounterWrapped
	}
	return
}

func (c *tentpConn) sendRecord(rec *tentpRecord) (err error) {
	// You better be holding c.sendLock.

	st := c.sendState // Save typing.

	// This is set if the counter happened to wrap, which is unlikely to happen
	// under any current practical use case as it requires transfering 2^64
	// records.
	if st.err != nil {
		return st.err
	}

	// Allocate a temporary buffer that will contain everything that goes onto
	// the network.
	//
	// Note: At this point rec.body includes the padding if any.
	wrLen := st.authLen + recordHeaderLen
	bLen := 0
	if rec.body != nil && len(rec.body) > 0 {
		bLen = len(rec.body)
		wrLen += st.authLen + bLen
	}
	b := make([]byte, 0, wrLen)

	// Key the ENC() stream cipher used to generate the one time keys.
	if err = st.enc.Key(st.key); err != nil {
		panic(err)
	}

	// Derive tentp_record_keys.authkey1, tentp_record_keys.authkey2.
	authKey1 := st.enc.KeyStream(st.authKeyLen)
	authKey2 := st.enc.KeyStream(st.authKeyLen)

	// Derive tentp_record_keys.header_stream, and encrypt the header.
	encHdr := make([]byte, recordHeaderLen)
	st.enc.XORKeyStream(encHdr, rec.hdr.Bytes())

	// Derive tentp_record_keys.body_stream, and encrypt the body.
	var encBody []byte
	if bLen > 0 {
		encBody = make([]byte, bLen)
		st.enc.XORKeyStream(encBody, rec.body)
	}

	// Serialize NSEND into network byte order.
	var nsend [counterLen]byte
	binary.BigEndian.PutUint64(nsend[:], st.ctr)

	// Derive tentp_encrypted_record.header_auth.
	if err = st.auth.Key(authKey1); err != nil {
		panic(err)
	}
	st.auth.Write(nsend[:])
	st.auth.Write(encHdr)
	hdrAuth := st.auth.Sum(nil)

	// Derive tentp_encrypted_record.body_auth.
	var bodyAuth []byte
	if bLen > 0 {
		if err = st.auth.Key(authKey2); err != nil {
			panic(err)
		}
		st.auth.Write(nsend[:])
		st.auth.Write(encBody)
		bodyAuth = st.auth.Sum(nil)
	}

	// Put it all together.
	b = append(b, hdrAuth...)
	b = append(b, encHdr...)
	if bLen > 0 {
		b = append(b, bodyAuth...)
		b = append(b, encBody...)
	}

	// Derive tentp_record_keys.next_key, and increment the counter.
	st.key = st.enc.KeyStream(st.encKeyLen)
	st.ctr++
	if st.ctr == 0 {
		// The counter wrapped, can't send anymore records past the one that
		// was just built.  Hope it was a CMD_CLOSE.
		st.err = ErrCounterWrapped
	}

	/* Send the record onto the network. */
	_, err = c.conn.Write(b)
	return err
}

func (c *tentpConn) forceClose() error {
	return c.conn.Close()
}

// WrapConn wraps an established net.Conn instance with a TENTP protocol
// handler.
func WrapConn(c net.Conn, a func() auth.Auth, e func() enc.Enc, krecv, ksend []byte) (net.Conn, error) {
	var err error
	tc := &tentpConn{conn: c}
	if tc.recvState, err = newKeyState(a(), e(), krecv); err != nil {
		return nil, err
	}
	if tc.sendState, err = newKeyState(a(), e(), ksend); err != nil {
		return nil, err
	}
	return tc, nil
}

var _ net.Conn = (*tentpConn)(nil)
