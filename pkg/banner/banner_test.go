package banner

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestIsWebPort(t *testing.T) {
	for _, p := range []int{80, 443, 8080, 8000} {
		if !IsWebPort(p) {
			t.Errorf("port %d should be a web port", p)
		}
	}
	for _, p := range []int{21, 22, 554, 25, 3306} {
		if IsWebPort(p) {
			t.Errorf("port %d should not be a web port", p)
		}
	}
}

func TestProbeHTTP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte(
			"HTTP/1.1 200 OK\r\n" +
				"Server: nginx/1.24.0\r\n" +
				"Content-Type: text/html\r\n\r\n" +
				"<html><head><title>Hello World</title></head><body>ok</body></html>",
		))
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	info := Probe(client, "10.0.0.1", 80, 16384)

	if !info.IsHTTP {
		t.Error("expected an HTTP probe")
	}
	if info.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", info.StatusCode)
	}
	if info.Server != "nginx/1.24.0" {
		t.Errorf("Server = %q, want nginx/1.24.0", info.Server)
	}
	if info.Title != "Hello World" {
		t.Errorf("Title = %q, want Hello World", info.Title)
	}
}

func TestProbeHTTPTitleAcrossLines(t *testing.T) {
	info := Info{}
	parseHTTP("HTTP/1.1 404 Not Found\r\nserver: Apache/2.4.41 (Ubuntu)\r\n\r\n<html>\n<title>\n  Not Found\n</title>\n</html>", &info)
	if info.StatusCode != 404 {
		t.Errorf("StatusCode = %d, want 404", info.StatusCode)
	}
	if info.Server != "Apache/2.4.41 (Ubuntu)" {
		t.Errorf("Server = %q", info.Server)
	}
	if info.Title != "Not Found" {
		t.Errorf("Title = %q, want 'Not Found'", info.Title)
	}
}

func TestProbeRawBanner(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = server.Write([]byte("220 Welcome to ProFTPD\r\n"))
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	info := Probe(client, "10.0.0.1", 21, 16384)

	if info.IsHTTP {
		t.Error("port 21 should not use an HTTP probe")
	}
	if info.Raw != "220 Welcome to ProFTPD" {
		t.Errorf("Raw = %q, want '220 Welcome to ProFTPD'", info.Raw)
	}
}

func TestProbeHTTPBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	body := strings.Repeat("x", 3000) + "<title>Big</title>" + strings.Repeat("y", 3000)
	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nServer: t\r\n\r\n" + body))
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	info := Probe(client, "10.0.0.1", 80, 8192)

	if info.Title != "Big" {
		t.Errorf("Title = %q, want Big", info.Title)
	}
	if len(info.Body) != len(body)+30 {
		t.Errorf("Body len = %d, want %d (body + headers)", len(info.Body), len(body)+30)
	}
	if len(info.Raw) > MaxRead {
		t.Errorf("Raw len = %d, must stay <= %d", len(info.Raw), MaxRead)
	}
	if !strings.Contains(info.Body, "<title>Big</title>") {
		t.Error("Body must keep the HTML")
	}
}

func TestSanitize(t *testing.T) {
	got := sanitize("a\x00b\x1f\x7f\xe2\x82\xac\nc")
	want := "ab\xe2\x82\xac\nc"
	if got != want {
		t.Errorf("sanitize = %q, want %q", got, want)
	}
}

func TestProbeFTPAnonymous(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		_, _ = server.Write([]byte("220 FTP Server ready\r\n"))
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("331 Guest login ok, send your complete e-mail address as password\r\n"))
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("230 Anonymous access granted\r\n"))
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("221 Goodbye\r\n"))
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	fi := ProbeFTP(client)

	if fi.Banner != "220 FTP Server ready" {
		t.Errorf("Banner = %q, want '220 FTP Server ready'", fi.Banner)
	}
	if fi.Auth != "anonymous" {
		t.Errorf("Auth = %q, want anonymous", fi.Auth)
	}
}

func TestProbeFTPDenied(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		_, _ = server.Write([]byte("220 FTP Server ready\r\n"))
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("331 Password required\r\n"))
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("530 Login incorrect\r\n"))
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	fi := ProbeFTP(client)

	if fi.Auth != "denied" {
		t.Errorf("Auth = %q, want denied", fi.Auth)
	}
}

func TestProbeDAVEnabled(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte(
			"HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\n\r\n" +
				"<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\"><d:response>" +
				"<d:href>/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>" +
				"</d:propstat></d:response></d:multistatus>",
		))
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	dav, body := ProbeDAV(client, "10.0.0.1")

	if !dav {
		t.Error("expected WebDAV to be detected")
	}
	if !strings.Contains(body, "multistatus") {
		t.Error("body should keep the PROPFIND response")
	}
}

func TestProbeDAVDisabled(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
	}()

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	dav, _ := ProbeDAV(client, "10.0.0.1")

	if dav {
		t.Error("405 should not be reported as WebDAV")
	}
}
