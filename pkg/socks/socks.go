// Package socks implements a minimal SOCKS5 client (RFC 1928) with
// username/password authentication (RFC 1929), enough to route scanner
// connections through TOR or any SOCKS5 proxy.
package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

const (
	ver5          = 5
	cmdConnect    = 1
	atypIPv4      = 1
	atypDomain    = 3
	repSuccess    = 0
	authNoAuth    = 0
	authUserPass  = 2
	authNoMethods = 0xFF
)

// Dialer dials TCP connections, possibly through a SOCKS5 proxy.
type Dialer struct {
	addr     string
	user     string
	pass     string
	timeout  time.Duration
	proxyURL string
}

// NewDialer parses a socks5://[user:pass@]host:port URL and returns a
// Dialer. An empty spec returns a nil Dialer (direct connections).
func NewDialer(spec string, timeout time.Duration) (*Dialer, error) {
	if spec == "" {
		return nil, nil
	}
	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy: %w", err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("invalid proxy: scheme %q (use socks5://host:port)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("invalid proxy: missing host")
	}
	if u.Port() == "" {
		return nil, errors.New("invalid proxy: missing port")
	}
	if _, err := strconv.Atoi(u.Port()); err != nil {
		return nil, fmt.Errorf("invalid proxy: %w", err)
	}
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Dialer{addr: net.JoinHostPort(host, u.Port()), user: user, pass: pass, timeout: timeout, proxyURL: spec}, nil
}

// URL returns the proxy spec as provided by the user.
func (d *Dialer) URL() string {
	if d == nil {
		return ""
	}
	return d.proxyURL
}

// Dial opens a TCP connection to addr through the SOCKS5 proxy.
func (d *Dialer) Dial(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", d.addr, d.timeout)
	if err != nil {
		return nil, fmt.Errorf("proxy connect: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(d.timeout))

	if err := handshake(conn, d.user, d.pass); err != nil {
		return nil, fmt.Errorf("proxy %s: %w", d.addr, err)
	}
	if err := connect(conn, addr); err != nil {
		return nil, fmt.Errorf("proxy %s: %w", d.addr, err)
	}
	ok = true
	return conn, nil
}

func handshake(conn net.Conn, user, pass string) error {
	methods := []byte{authNoAuth}
	if user != "" {
		methods = append(methods, authUserPass)
	}
	greet := append([]byte{ver5, byte(len(methods))}, methods...)
	if _, err := conn.Write(greet); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := readFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != ver5 {
		return errors.New("versión SOCKS no soportada")
	}
	switch resp[1] {
	case authNoAuth:
		return nil
	case authUserPass:
		return userPassAuth(conn, user, pass)
	case authNoMethods:
		return errors.New("proxy rejected all authentication methods")
	default:
		return fmt.Errorf("unexpected auth method %d", resp[1])
	}
}

func userPassAuth(conn net.Conn, user, pass string) error {
	if user == "" || len(user) > 255 || len(pass) > 255 {
		return errors.New("credenciales SOCKS inválidas")
	}
	msg := []byte{1, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := readFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 1 || resp[1] != 0 {
		return errors.New("autenticación de usuario/contraseña falló")
	}
	return nil
}

func connect(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q", portStr)
	}
	var atyp byte
	var dst []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			atyp = atypIPv4
			dst = ip4
		} else {
			return errors.New("IPv6 addresses are not supported")
		}
	} else {
		if len(host) > 255 {
			return errors.New("hostname too long")
		}
		atyp = atypDomain
		dst = append([]byte{byte(len(host))}, host...)
	}
	req := []byte{ver5, cmdConnect, 0, atyp}
	req = append(req, dst...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 4)
	if _, err := readFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != ver5 {
		return errors.New("versión SOCKS no soportada en la respuesta")
	}
	if resp[1] != repSuccess {
		return fmt.Errorf("CONNECT rechazado (código %d)", resp[1])
	}
	// addr type (1) + address (4/255) + port (2)
	skip := 0
	switch resp[3] {
	case atypIPv4:
		skip = 4
	case atypDomain:
		b := make([]byte, 1)
		if _, err := readFull(conn, b); err != nil {
			return err
		}
		skip = int(b[0])
	default:
		skip = 16
	}
	if skip > 0 {
		if _, err := readFull(conn, make([]byte, skip)); err != nil {
			return err
		}
	}
	if _, err := readFull(conn, make([]byte, 2)); err != nil {
		return err
	}
	return nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
