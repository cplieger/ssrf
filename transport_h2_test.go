package ssrf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// h2Server starts an HTTP/2 TLS server that answers every request with
// "ok" followed by the request body.
func h2Server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
		_, _ = io.Copy(w, r.Body)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// h2Transport is SafeTransport opened to the loopback port of addr, trusting
// srv's certificate, at a scaled header timeout and PING window.
func h2Transport(t *testing.T, srv *httptest.Server, addr string, h2 *http.HTTP2Config) *http.Transport {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("ParseUint(%q) error = %v", portStr, err)
	}
	tr := SafeTransport(WithAddressPolicy(func(netip.Addr) bool { return true }), WithAllowedPorts(uint16(port)))
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	tr.ResponseHeaderTimeout = 3 * time.Second
	tr.HTTP2 = h2
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

// silencingProxy forwards TCP to a target until silence is called, after which
// every connection it already accepted drops its bytes in both directions while
// new connections forward normally: a peer that went silent mid-connection.
type silencingProxy struct {
	ln       net.Listener
	target   string
	mu       sync.Mutex
	conns    []net.Conn
	silent   []*atomic.Bool
	accepted atomic.Int32
}

func newSilencingProxy(t *testing.T, target string) *silencingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	p := &silencingProxy{ln: ln, target: target}
	go p.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, c := range p.conns {
			_ = c.Close()
		}
	})
	return p
}

func (p *silencingProxy) serve() {
	for {
		down, err := p.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = down.Close()
			continue
		}
		silent := new(atomic.Bool)
		p.mu.Lock()
		p.conns = append(p.conns, down, up)
		p.silent = append(p.silent, silent)
		p.mu.Unlock()
		p.accepted.Add(1)
		go pipeUnlessSilent(up, down, silent)
		go pipeUnlessSilent(down, up, silent)
	}
}

func (p *silencingProxy) silence() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.silent {
		s.Store(true)
	}
}

func pipeUnlessSilent(dst, src net.Conn, silent *atomic.Bool) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if silent.Load() {
			continue
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

type h2Answer struct {
	proto      string
	body       string
	protoMajor int
	status     int
}

// h2Do sends one request and returns its answer with the body read out.
func h2Do(ctx context.Context, cl *http.Client, method, url, body string) (h2Answer, error) {
	var rd io.Reader = http.NoBody
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return h2Answer{}, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return h2Answer{}, err
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	return h2Answer{proto: resp.Proto, body: string(got), protoMajor: resp.ProtoMajor, status: resp.StatusCode}, err
}

// The scaled window (2 s + 600 ms) sits below the 3 s header timeout, the
// shipped ratio, so the request on the silent connection ends before its
// header timeout and the next one dials.
func TestSafeTransport_HTTP2PingClosesSilentConn(t *testing.T) {
	t.Parallel()
	srv := h2Server(t)
	p := newSilencingProxy(t, srv.Listener.Addr().String())
	tr := h2Transport(t, srv, p.ln.Addr().String(), &http.HTTP2Config{
		SendPingTimeout: 2 * time.Second,
		PingTimeout:     600 * time.Millisecond,
	})
	cl := &http.Client{Transport: tr}
	url := "https://" + p.ln.Addr().String() + "/"

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ans, err := h2Do(ctx, cl, http.MethodGet, url, "")
	if err != nil {
		t.Fatalf("first GET error = %v", err)
	}
	if ans.protoMajor != 2 {
		t.Fatalf("first GET proto = %s, want HTTP/2", ans.proto)
	}

	p.silence()
	if _, err := h2Do(ctx, cl, http.MethodGet, url, ""); err == nil || !strings.Contains(err.Error(), "client connection lost") {
		t.Fatalf("GET on the silent connection error = %v, want http2: client connection lost", err)
	}

	if _, err := h2Do(ctx, cl, http.MethodGet, url, ""); err != nil {
		t.Fatalf("GET after the silent connection closed error = %v, want an answer on a new connection", err)
	}
	if got := p.accepted.Load(); got != 2 {
		t.Errorf("connections opened = %d, want 2 (the silent one and its replacement)", got)
	}
}

const (
	h2FrameHeaders  = 0x1
	h2FrameSettings = 0x4
	h2FramePing     = 0x6
	h2FrameGoAway   = 0x7

	h2FlagAck        = 0x1
	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4

	h2ErrEnhanceYourCalm = 0xb
)

// goAwayListener serves its first connection with calmServer and forwards
// every later one to target.
type goAwayListener struct {
	ln       net.Listener
	target   string
	cert     []tls.Certificate
	accepted atomic.Int32
	pinged   chan struct{} // closed once the GOAWAY answering the PING is written
	closed   chan struct{} // closed once the client closed the first connection
	mu       sync.Mutex
	conns    []net.Conn
}

func newGoAwayListener(t *testing.T, srv *httptest.Server) *goAwayListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	l := &goAwayListener{
		ln:     ln,
		target: srv.Listener.Addr().String(),
		cert:   srv.TLS.Certificates,
		pinged: make(chan struct{}),
		closed: make(chan struct{}),
	}
	go l.serve(t)
	t.Cleanup(func() {
		_ = ln.Close()
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, c := range l.conns {
			_ = c.Close()
		}
	})
	return l
}

func (l *goAwayListener) track(c net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.conns = append(l.conns, c)
}

func (l *goAwayListener) serve(t *testing.T) {
	for {
		down, err := l.ln.Accept()
		if err != nil {
			return
		}
		l.track(down)
		if l.accepted.Add(1) == 1 {
			go l.calmServer(t, down)
			continue
		}
		up, err := net.Dial("tcp", l.target)
		if err != nil {
			_ = down.Close()
			continue
		}
		l.track(up)
		go func() { _, _ = io.Copy(up, down) }()
		go func() { _, _ = io.Copy(down, up) }()
	}
}

// calmServer is a minimal HTTP/2 server (RFC 9113) that answers one request
// with an empty 200 and answers a PING with GOAWAY ENHANCE_YOUR_CALM, as a
// server limiting pings does. It is written by hand because net/http's server
// acknowledges every PING itself.
func (l *goAwayListener) calmServer(t *testing.T, raw net.Conn) {
	conn := tls.Server(raw, &tls.Config{Certificates: l.cert, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	defer close(l.closed)
	defer conn.Close()
	preface := make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if _, err := io.ReadFull(conn, preface); err != nil {
		t.Errorf("calmServer: reading the client preface: %v", err)
		return
	}
	if err := writeH2Frame(conn, h2FrameSettings, 0, 0, nil); err != nil {
		t.Errorf("calmServer: writing SETTINGS: %v", err)
		return
	}
	var lastStream uint32
	for {
		typ, flags, stream, err := readH2Frame(conn)
		if err != nil {
			return
		}
		switch {
		case typ == h2FrameSettings && flags&h2FlagAck == 0:
			err = writeH2Frame(conn, h2FrameSettings, h2FlagAck, 0, nil)
		case typ == h2FrameHeaders:
			lastStream = stream
			// 0x88 is the HPACK static-table index of ":status: 200" (RFC 7541 Appendix A).
			err = writeH2Frame(conn, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, stream, []byte{0x88})
		case typ == h2FramePing && flags&h2FlagAck == 0:
			payload := binary.BigEndian.AppendUint32(nil, lastStream)
			payload = binary.BigEndian.AppendUint32(payload, h2ErrEnhanceYourCalm)
			if err = writeH2Frame(conn, h2FrameGoAway, 0, 0, payload); err == nil {
				close(l.pinged)
			}
		}
		if err != nil {
			t.Errorf("calmServer: answering frame type %#x: %v", typ, err)
			return
		}
	}
}

func writeH2Frame(w io.Writer, typ, flags byte, stream uint32, payload []byte) error {
	n := len(payload)
	frame := []byte{byte(n >> 16), byte(n >> 8), byte(n), typ, flags}
	frame = binary.BigEndian.AppendUint32(frame, stream)
	_, err := w.Write(append(frame, payload...))
	return err
}

func readH2Frame(r io.Reader) (typ, flags byte, stream uint32, err error) {
	var hdr [9]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, 0, err
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if _, err = io.CopyN(io.Discard, r, int64(n)); err != nil {
		return 0, 0, 0, err
	}
	return hdr[3], hdr[4], binary.BigEndian.Uint32(hdr[5:]) &^ (1 << 31), nil
}

// A server that answers the health check's PING with GOAWAY ENHANCE_YOUR_CALM
// ends only the idle connection: the next GET, and a POST whose body must be
// sent again in full, answer on a new one.
func TestSafeTransport_HTTP2GoAwayOnIdlePing(t *testing.T) {
	t.Parallel()
	srv := h2Server(t)
	l := newGoAwayListener(t, srv)
	// PingTimeout outlasts the close wait below, so only the GOAWAY can close
	// the connection in time.
	tr := h2Transport(t, srv, l.ln.Addr().String(), &http.HTTP2Config{
		SendPingTimeout: 1 * time.Second,
		PingTimeout:     10 * time.Second,
	})
	cl := &http.Client{Transport: tr}
	url := "https://" + l.ln.Addr().String() + "/"

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ans, err := h2Do(ctx, cl, http.MethodGet, url, "")
	if err != nil {
		t.Fatalf("GET on the first connection error = %v", err)
	}
	if ans.protoMajor != 2 || ans.status != http.StatusOK {
		t.Fatalf("GET on the first connection = %s %d, want HTTP/2.0 200", ans.proto, ans.status)
	}

	select {
	case <-l.pinged:
	case <-time.After(5 * time.Second):
		t.Fatal("precondition: the idle connection received no PING within 5s, so no GOAWAY was written")
	}
	select {
	case <-l.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("precondition: the client did not close the connection within 2s of its GOAWAY")
	}

	ans, err = h2Do(ctx, cl, http.MethodGet, url, "")
	if err != nil {
		t.Fatalf("GET after the GOAWAY error = %v, want an answer on a new connection", err)
	}
	if ans.protoMajor != 2 {
		t.Errorf("GET after the GOAWAY proto = %s, want HTTP/2", ans.proto)
	}
	ans, err = h2Do(ctx, cl, http.MethodPost, url, "payload")
	if err != nil {
		t.Fatalf("POST after the GOAWAY error = %v, want an answer on a new connection", err)
	}
	if ans.status != http.StatusOK || ans.body != "okpayload" {
		t.Errorf("POST after the GOAWAY = %d %q, want 200 %q", ans.status, ans.body, "okpayload")
	}
	if got := l.accepted.Load(); got != 2 {
		t.Errorf("connections opened = %d, want 2 (the one sent GOAWAY and its replacement)", got)
	}
}
