package secureconn

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	tagSuite   = "SIGNATORY_SECURE_CONNECTION_X25519_ED25519"
	tagSecret  = "DH_SECRET"
	tagEphKeys = "EPHEMERAL_PUBLIC_KEYS_XOR_COMBINED"
	tagAuth    = "AUTHENTICATION_PUBLIC_KEYS_XOR_COMBINED"
	tagLen     = "SIGNATORY_SECURE_CONNECTION_LENGTH_KEY"
	tagPayload = "SIGNATORY_SECURE_CONNECTION_PAYLOAD_KEY"
)

const (
	granularity    = 64
	maxMessageSize = 65536
)

type SecureConn struct {
	conn                    net.Conn
	readCipher, writeCipher packetCipher
	remotePub               ed25519.PublicKey
	sessionID               []byte
	readBuf                 []byte
}

type sessionKeys struct {
	rdLength  []byte
	rdPayload []byte
	wrLength  []byte
	wrPayload []byte
}

type helloMessage struct {
	_                  struct{} `cbor:",toarray"`
	EphemeralPublicKey []byte
	AuthPublicKey      *ed25519.PublicKey
}

type authMessage struct {
	_                  struct{} `cbor:",toarray"`
	ChallengeSignature *[]byte
}

func curve() ecdh.Curve { return ecdh.X25519() }

func combineKeys(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("inconsistent key lengths")
	}
	out := make([]byte, len(a))
	for i := range len(a) {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func genSingle(prk []byte, info []byte, tag string) []byte {
	kdf, _ := blake2b.New256(prk)
	kdf.Write([]byte(tag))
	kdf.Write(info)
	return kdf.Sum(nil)
}

func generateKeys(localEph, remoteEph *ecdh.PublicKey, secret []byte) sessionKeys {
	loc := new(big.Int).SetBytes(localEph.Bytes())
	rem := new(big.Int).SetBytes(remoteEph.Bytes())

	rDiff := new(big.Int).Sub(loc, rem)
	wDiff := new(big.Int).Neg(rDiff)

	rSign := byte(0)
	if rDiff.Sign() < 0 {
		rSign = 1
	}
	wSign := byte(0)
	if wDiff.Sign() < 0 {
		wSign = 1
	}

	rBytesRaw := rDiff.Bytes()
	wBytesRaw := wDiff.Bytes()

	rBytes := make([]byte, 1+len(rBytesRaw))
	wBytes := make([]byte, 1+len(wBytesRaw))
	rBytes[0] = rSign
	wBytes[0] = wSign
	copy(rBytes[1:], rBytesRaw)
	copy(wBytes[1:], wBytesRaw)

	prk := blake2b.Sum256(secret)

	keys := sessionKeys{
		rdLength:  genSingle(prk[:], rBytes, tagLen),
		rdPayload: genSingle(prk[:], rBytes, tagPayload),
		wrLength:  genSingle(prk[:], wBytes, tagLen),
		wrPayload: genSingle(prk[:], wBytes, tagPayload),
	}

	return keys
}

type encodedReadWriter interface {
	ReadMessage(v any) error
	WriteMessage(v any) error
}

type cborConn struct {
	conn net.Conn
}

func (c *cborConn) ReadMessage(v any) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
		return err
	}

	msgLen := binary.BigEndian.Uint32(lenBuf[:])
	if msgLen > maxMessageSize {
		return fmt.Errorf("message too large: %d", msgLen)
	}

	data := make([]byte, msgLen)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return err
	}

	return cbor.Unmarshal(data, v)
}

func (c *cborConn) WriteMessage(v any) error {
	data, err := cbor.Marshal(v)
	if err != nil {
		return err
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := c.conn.Write(lenBuf); err != nil {
		return err
	}
	if _, err := c.conn.Write(data); err != nil {
		return err
	}
	return nil
}

func exchange[T any, C encodedReadWriter](c C, data *T) (out *T, err error) {
	out = new(T)
	errCh := make(chan error, 2)

	go func() {
		errCh <- c.WriteMessage(data)
	}()

	go func() {
		errCh <- c.ReadMessage(out)
	}()

	for range 2 {
		e := <-errCh
		if err == nil {
			err = e
		}
	}
	return
}

func WrapConnection(conn net.Conn, serverPublicKey ed25519.PublicKey, clientPrivateKey ed25519.PrivateKey) (net.Conn, error) {
	return NewSecureConn(conn, clientPrivateKey, serverPublicKey)
}

func NewSecureConn(transport net.Conn, localKey ed25519.PrivateKey, expectedRemoteKey ed25519.PublicKey) (*SecureConn, error) {
	eph, err := curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	rawConn := &cborConn{conn: transport}

	localPub := localKey.Public().(ed25519.PublicKey)

	helloResult, err := exchange(rawConn, &helloMessage{
		EphemeralPublicKey: eph.PublicKey().Bytes(),
		AuthPublicKey:      &localPub,
	})
	if err != nil {
		return nil, fmt.Errorf("hello exchange failed: %w", err)
	}

	if helloResult.AuthPublicKey == nil || len(*helloResult.AuthPublicKey) == 0 || len(helloResult.EphemeralPublicKey) == 0 {
		return nil, errors.New("invalid handshake message")
	}

	if !helloResult.AuthPublicKey.Equal(expectedRemoteKey) {
		return nil, errors.New("remote public key mismatch")
	}

	remoteEphPub, err := curve().NewPublicKey(helloResult.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid remote ephemeral key: %w", err)
	}
	remotePub := helloResult.AuthPublicKey

	secret, err := eph.ECDH(remoteEphPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	combinedEphKeys := combineKeys(eph.PublicKey().Bytes(), remoteEphPub.Bytes())
	combinedAuthKeys := combineKeys(localPub[:], (*remotePub)[:])

	ch, _ := blake2b.New256(nil)
	ch.Write([]byte(tagSuite))
	ch.Write([]byte(tagEphKeys))
	ch.Write(combinedEphKeys)
	ch.Write([]byte(tagAuth))
	ch.Write(combinedAuthKeys)
	ch.Write([]byte(tagSecret))
	ch.Write(secret)
	challenge := ch.Sum(nil)

	sig := ed25519.Sign(localKey, challenge)

	authResult, err := exchange(rawConn, &authMessage{
		ChallengeSignature: &sig,
	})
	if err != nil {
		return nil, fmt.Errorf("auth exchange failed: %w", err)
	}

	if authResult.ChallengeSignature == nil || len(*authResult.ChallengeSignature) == 0 {
		return nil, errors.New("invalid auth message")
	}

	if !ed25519.Verify((*remotePub), challenge, *authResult.ChallengeSignature) {
		return nil, errors.New("authentication failed: signature verification failed")
	}

	keys := generateKeys(eph.PublicKey(), remoteEphPub, secret)

	sc := &SecureConn{
		conn:        transport,
		readCipher:  newPacketCipher(keys.rdLength, keys.rdPayload),
		writeCipher: newPacketCipher(keys.wrLength, keys.wrPayload),
		remotePub:   (*remotePub),
		sessionID:   challenge,
	}

	return sc, nil
}

type packetCipher struct {
	lengthKey     []byte
	payloadCipher cipher.AEAD
	buf           []byte
	nonce         uint64
}

func newPacketCipher(lengthKey, payloadKey []byte) packetCipher {
	plCipher, err := chacha20poly1305.New(payloadKey)
	if err != nil {
		panic(err)
	}

	return packetCipher{
		lengthKey:     lengthKey,
		payloadCipher: plCipher,
	}
}

func (p *packetCipher) readPacket(r io.Reader) ([]byte, error) {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:], p.nonce)

	var encLengthBuf [4]byte
	if _, err := io.ReadFull(r, encLengthBuf[:]); err != nil {
		return nil, err
	}

	lc, err := chacha20.NewUnauthenticatedCipher(p.lengthKey, nonce[:])
	if err != nil {
		panic(err)
	}
	var lengthBuf [4]byte
	lc.XORKeyStream(lengthBuf[:], encLengthBuf[:])
	length := int(binary.BigEndian.Uint32(lengthBuf[:]))

	if length < chacha20poly1305.Overhead+4 {
		return nil, errors.New("packet is too short")
	}

	if len(p.buf) < length {
		p.buf = make([]byte, length)
	}
	payload := p.buf[:length]
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	if _, err = p.payloadCipher.Open(payload[:0], nonce[:], payload, encLengthBuf[:]); err != nil {
		return nil, err
	}

	p.nonce++

	unpaddedLength := int(binary.BigEndian.Uint32(payload[:4]))
	if unpaddedLength > length-4-chacha20poly1305.Overhead {
		return nil, errors.New("invalid unpadded length")
	}

	result := payload[4 : 4+unpaddedLength]
	return result, nil
}

func (p *packetCipher) writePacket(w io.Writer, data []byte) error {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:], p.nonce)

	total := 4 + 4 + len(data) + chacha20poly1305.Overhead
	padded := (total + granularity - 1) &^ (granularity - 1)

	if len(p.buf) < padded {
		p.buf = make([]byte, padded)
	}

	length := padded - 4
	dataLen := length - chacha20poly1305.Overhead

	lc, err := chacha20.NewUnauthenticatedCipher(p.lengthKey, nonce[:])
	if err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint32(p.buf[:4], uint32(length))
	lc.XORKeyStream(p.buf[:4], p.buf[:4])

	payload := p.buf[4 : 4+dataLen]
	binary.BigEndian.PutUint32(payload[:4], uint32(len(data)))
	copy(payload[4:], data)

	toPad := payload[4+len(data) : dataLen]
	if len(toPad) != 0 {
		rand.Read(toPad)
	}

	p.payloadCipher.Seal(payload[:0], nonce[:], payload, p.buf[:4])

	packet := p.buf[:padded]
	if _, err = w.Write(packet); err != nil {
		return err
	}

	p.nonce++
	return nil
}

func (sc *SecureConn) ReadPacket() ([]byte, error) {
	return sc.readCipher.readPacket(sc.conn)
}

func (sc *SecureConn) WritePacket(data []byte) error {
	return sc.writeCipher.writePacket(sc.conn, data)
}

func (sc *SecureConn) Read(b []byte) (int, error) {
	if len(sc.readBuf) > 0 {
		n := copy(b, sc.readBuf)
		sc.readBuf = sc.readBuf[n:]
		return n, nil
	}

	data, err := sc.ReadPacket()
	if err != nil {
		return 0, err
	}

	n := copy(b, data)
	if n < len(data) {
		sc.readBuf = data[n:]
	}
	return n, nil
}

func (sc *SecureConn) Write(b []byte) (int, error) {
	if err := sc.WritePacket(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (sc *SecureConn) RemotePublicKey() ed25519.PublicKey {
	return sc.remotePub
}

func (sc *SecureConn) SessionID() []byte {
	return sc.sessionID
}

func (sc *SecureConn) Close() error {
	return sc.conn.Close()
}

func (sc *SecureConn) LocalAddr() net.Addr {
	return sc.conn.LocalAddr()
}

func (sc *SecureConn) RemoteAddr() net.Addr {
	return sc.conn.RemoteAddr()
}

func (sc *SecureConn) SetDeadline(t time.Time) error {
	return sc.conn.SetDeadline(t)
}

func (sc *SecureConn) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

func (sc *SecureConn) SetWriteDeadline(t time.Time) error {
	return sc.conn.SetWriteDeadline(t)
}
