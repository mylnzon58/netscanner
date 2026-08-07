package socks

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// startFakeProxy levanta un proxy SOCKS5 mínimo que acepta cualquier
// método y se conecta a la dirección pedida, devolviendo la primera
// línea del destino.
func startFakeProxy(t *testing.T, requireAuth bool) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleProxyConn(c, requireAuth)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func handleProxyConn(c net.Conn, requireAuth bool) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		return
	}
	methods := make([]byte, int(greet[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// saludo: contestar no-auth o user/pass
	if requireAuth {
		_, _ = c.Write([]byte{5, 2})
		auth := make([]byte, 2)
		if _, err := io.ReadFull(c, auth); err != nil {
			return
		}
		if auth[0] != 1 {
			return
		}
		user := make([]byte, int(auth[1]))
		if _, err := io.ReadFull(c, user); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(c, plen); err != nil {
			return
		}
		pass := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(c, pass); err != nil {
			return
		}
		if string(user) != "anon" || string(pass) != "secreto" {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		_, _ = c.Write([]byte{1, 0})
	} else {
		_, _ = c.Write([]byte{5, 0})
	}
	// pedido CONNECT
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	var host string
	switch hdr[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		blen := make([]byte, 1)
		if _, err := io.ReadFull(c, blen); err != nil {
			return
		}
		b := make([]byte, int(blen[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		return
	}
	portB := make([]byte, 2)
	if _, err := io.ReadFull(c, portB); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portB)
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 5*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	// reenviar una sola línea del destino al cliente (alcanza para el test)
	b := make([]byte, 128)
	if n, err := target.Read(b); err == nil {
		_, _ = c.Write(b[:n])
	}
}

func TestSocks5ConnectNoAuth(t *testing.T) {
	addr, stop := startFakeProxy(t, false)
	defer stop()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("hola-proxy\n"))
	}()

	d, err := NewDialer("socks5://"+addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.Dial(target.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hola-proxy\n" {
		t.Fatalf("recibido %q", buf[:n])
	}
}

func TestSocks5ConnectWithAuth(t *testing.T) {
	addr, stop := startFakeProxy(t, true)
	defer stop()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("ok-auth\n"))
	}()

	d, err := NewDialer("socks5://anon:secreto@"+addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.Dial(target.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "ok-auth\n" {
		t.Fatalf("recibido %q", buf[:n])
	}
}

func TestSocks5BadAuth(t *testing.T) {
	addr, stop := startFakeProxy(t, true)
	defer stop()
	d, err := NewDialer("socks5://mal:clave@"+addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Dial("127.0.0.1:9999"); err == nil {
		t.Fatal("esperaba error de autenticación")
	}
}
