package vless

import (
	"bytes"
	"io"
	"net"
	"strings"

	"github.com/gofrs/uuid/v5"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// X365Marker switches the connection to the airport's private "X365" wire
// format. It is a suffix of the uuid and never part of the uuid itself.
const X365Marker = "#x365"

// SplitX365UUID strips the marker and reports whether it was present.
func SplitX365UUID(raw string) (string, bool) {
	if strings.HasSuffix(strings.ToLower(raw), X365Marker) {
		return raw[:len(raw)-len(X365Marker)], true
	}
	return raw, false
}

// x365Conn writes the private request frame on the first write and validates
// the 5-byte response header on the first read.
//
//	'X' '3' '6' '5' 0x01 | command | uuid(16) | port(2) | atyp | addr | payload
type x365Conn struct {
	net.Conn
	id       uuid.UUID
	dst      M.Socksaddr
	written  bool
	received bool
}

func newX365Conn(conn net.Conn, id uuid.UUID, dst M.Socksaddr) *x365Conn {
	return &x365Conn{Conn: conn, id: id, dst: dst}
}

func (c *x365Conn) buildRequest(payload []byte) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Write([]byte{'X', '3', '6', '5', 0x01})
	buffer.WriteByte(0x01) // command: TCP
	buffer.Write(c.id.Bytes())
	buffer.Write([]byte{byte(c.dst.Port >> 8), byte(c.dst.Port)})
	switch {
	case c.dst.IsIPv4():
		buffer.WriteByte(0x01)
		addr := c.dst.Addr.As4()
		buffer.Write(addr[:])
	case c.dst.IsIPv6():
		buffer.WriteByte(0x04)
		addr := c.dst.Addr.As16()
		buffer.Write(addr[:])
	case c.dst.IsDomain():
		host := []byte(c.dst.Fqdn)
		if len(host) > 255 {
			return nil, E.New("x365: destination domain too long")
		}
		buffer.WriteByte(0x03)
		buffer.WriteByte(byte(len(host)))
		buffer.Write(host)
	default:
		return nil, E.New("x365: invalid destination")
	}
	buffer.Write(payload)
	return buffer.Bytes(), nil
}

func (c *x365Conn) Write(p []byte) (int, error) {
	if c.written {
		return c.Conn.Write(p)
	}
	request, err := c.buildRequest(p)
	if err != nil {
		return 0, err
	}
	if _, err = c.Conn.Write(request); err != nil {
		return 0, err
	}
	c.written = true
	return len(p), nil
}

func (c *x365Conn) Read(p []byte) (int, error) {
	if !c.received {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		if header[0] != 'X' || header[1] != '3' || header[2] != '6' || header[3] != '5' {
			return 0, E.New("x365: invalid response header")
		}
		c.received = true
	}
	return c.Conn.Read(p)
}

func (c *x365Conn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *x365Conn) Upstream() any {
	return c.Conn
}
