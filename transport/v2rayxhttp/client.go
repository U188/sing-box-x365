package v2rayxhttp

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

// DefaultUserAgent is what the airport's private endpoints expect; their edge
// rejects any other User-Agent with "403 Forbidden".
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

const (
	defaultPaddingMin = 100
	defaultPaddingMax = 1000
)

type Client struct {
	transport  common.TypedValue[http.RoundTripper]
	requestURL url.URL
	host       string
	method     string
	headers    http.Header
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if tlsConfig == nil {
		return nil, C.ErrTLSRequired
	}
	tlsDialer := tls.NewDialer(dialer, tlsConfig)
	// The ALPN list stays as configured so the ClientHello keeps its browser
	// shape (REALITY verifies it), while stream-one always speaks HTTP/2: this
	// endpoint answers HTTP/1.1 with 200 and then never streams the downlink.
	transport := &http2.Transport{
		ReadIdleTimeout: time.Duration(options.IdleTimeout),
		PingTimeout:     time.Duration(options.PingTimeout),
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.STDConfig) (net.Conn, error) {
			return tlsDialer.DialTLSContext(ctx, M.ParseSocksaddr(addr))
		},
	}
	method := options.Method
	if method == "" {
		method = http.MethodPost
	}
	requestPath := options.Path
	if requestPath == "" {
		requestPath = "/"
	}
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	// Session placement defaults to the path, so the uplink URL keeps a
	// trailing slash even when no session id is appended.
	if !strings.HasSuffix(requestPath, "/") {
		requestPath += "/"
	}
	var requestURL url.URL
	requestURL.Scheme = "https"
	requestURL.Host = serverAddr.String()
	requestURL.Path = requestPath

	headers := options.Headers.Build()
	if headers == nil {
		headers = make(http.Header)
	}
	requestHost := ""
	switch len(options.Host) {
	case 0:
		if hostHeader := headers.Get("Host"); hostHeader != "" {
			requestHost = hostHeader
		} else {
			requestHost = serverAddr.AddrString()
		}
		headers.Del("Host")
	case 1:
		requestHost = options.Host[0]
		headers.Del("Host")
	default:
		requestHost = options.Host[rand.Intn(len(options.Host))]
		headers.Del("Host")
	}
	if headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", DefaultUserAgent)
	}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/grpc")
	}
	client := &Client{
		requestURL: requestURL,
		host:       requestHost,
		method:     method,
		headers:    headers,
	}
	client.transport.Store(transport)
	return client, nil
}

func paddingReferer(requestURL url.URL, host string) string {
	referer := url.URL{Scheme: requestURL.Scheme, Host: host, Path: requestURL.Path}
	query := referer.Query()
	length := defaultPaddingMin + rand.Intn(defaultPaddingMax-defaultPaddingMin+1)
	query.Set("x_padding", strings.Repeat("X", length))
	referer.RawQuery = query.Encode()
	return referer.String()
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	pipeInReader, pipeInWriter := io.Pipe()
	requestCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	headers := c.headers.Clone()
	headers.Set("Referer", paddingReferer(c.requestURL, c.host))
	request := &http.Request{
		Method: c.method,
		Body:   pipeInReader,
		URL:    &c.requestURL,
		Header: headers,
		Host:   c.host,
	}
	request = request.WithContext(requestCtx)
	conn := v2rayhttp.NewLateHTTPConn(pipeInWriter, cancel)
	handshakeTimeout := C.TCPTimeout
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		handshakeTimeout = time.Until(deadline)
	}
	var handshakeTimedOut atomic.Bool
	handshakeTimer := time.AfterFunc(handshakeTimeout, func() {
		handshakeTimedOut.Store(true)
		cancel()
	})
	go func() {
		response, err := c.transport.Load().RoundTrip(request)
		handshakeTimer.Stop()
		if err != nil {
			if handshakeTimedOut.Load() {
				err = os.ErrDeadlineExceeded
			}
			conn.Setup(nil, err)
		} else if response.StatusCode != http.StatusOK {
			response.Body.Close()
			cancel()
			conn.Setup(nil, E.New("xhttp: unexpected status: ", response.Status))
		} else {
			conn.Setup(response.Body, nil)
		}
	}()
	return conn, nil
}

// CloseIdleConnections drops pooled HTTP/2 connections; ResetTransport also
// handles the http2.Transport case that CloseIdleConnections cannot see.
func (c *Client) CloseIdleConnections() {
	c.transport.Store(v2rayhttp.ResetTransport(c.transport.Load()))
}

func (c *Client) Close() error {
	c.transport.Store(v2rayhttp.ResetTransport(c.transport.Load()))
	return nil
}
