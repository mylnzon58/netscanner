// Package banner extrae la "huella" de un servicio: para los puertos
// web lanza un request HTTP y analiza la respuesta, y para el resto
// lee el banner que el servicio manda al conectarse.
package banner

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MaxRead es el máximo de bytes que se leen de una conexión.
const MaxRead = 4096

// UserAgent es el User-Agent HTTP que mandan los sondeos. Es neutro a
// propósito: los servidores no pueden deducir que es un escáner.
var UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

// DialTCP abre una conexión TCP. Se puede reemplazar para mandar los
// sondeos por un proxy SOCKS5 (FTPList también lo usa).
var DialTCP = func(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}

var (
	titleRe  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	webPorts = map[int]bool{
		80:   true,
		443:  true,
		8080: true,
		8000: true,
		5000: true,
		5001: true,
		8081: true,
		9000: true,
	}
)

// Info guarda todo lo que se aprendió de un puerto abierto.
type Info struct {
	IsHTTP     bool
	StatusCode int
	Server     string
	Title      string
	Raw        string
	Body       string
	FTPAuth    string
	FTPBanner  string
	DAV        bool
	DAVBody    string
}

// IsWebPort dice si el puerto se sondea con HTTP.
func IsWebPort(port int) bool { return webPorts[port] }

// Probe inspecciona una conexión abierta: para puertos web manda un
// request HTTP y parsea la respuesta, y para el resto lee el banner de
// bienvenida. maxBody limita los bytes capturados del cuerpo (0 usa
// MaxRead). La conexión ya debe tener deadline.
func Probe(conn net.Conn, ip string, port int, maxBody int) Info {
	if IsWebPort(port) {
		return probeHTTP(conn, ip, maxBody)
	}
	return readRaw(conn)
}

func probeHTTP(conn net.Conn, ip string, maxBody int) Info {
	info := Info{IsHTTP: true}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", ip, UserAgent)
	if _, err := conn.Write([]byte(req)); err != nil {
		return info
	}
	limit := MaxRead
	if maxBody > MaxRead {
		limit = maxBody
	}
	data := sanitize(readBounded(conn, limit))
	parseHTTP(data, &info)
	info.Raw = truncate(strings.TrimSpace(data), MaxRead)
	info.Body = strings.TrimSpace(data)
	return info
}

func readRaw(conn net.Conn) Info {
	return Info{Raw: strings.TrimSpace(sanitize(readBounded(conn, MaxRead)))}
}

// FTPInfo guarda el resultado del intento de login FTP anónimo.
type FTPInfo struct {
	Banner string
	Auth   string // "", "anonymous" o "denied"
}

// ProbeFTP lee el banner de bienvenida e intenta un login anónimo
// (USER/PASS anonymous). La conexión ya debe tener deadline.
func ProbeFTP(conn net.Conn) FTPInfo {
	fi := FTPInfo{}
	br := bufio.NewReader(conn)
	read := func() string {
		line, _ := br.ReadString('\n')
		return strings.TrimSpace(line)
	}
	line := read()
	if !strings.HasPrefix(line, "220") {
		return fi
	}
	for strings.HasPrefix(line, "220-") {
		line = read()
	}
	fi.Banner = line
	send := func(cmd string) string {
		_, _ = conn.Write([]byte(cmd + "\r\n"))
		return read()
	}
	switch r := send("USER anonymous"); {
	case strings.HasPrefix(r, "331") || strings.HasPrefix(r, "230"):
		if strings.HasPrefix(send("PASS anonymous@"), "230") {
			fi.Auth = "anonymous"
		} else {
			fi.Auth = "denied"
		}
	case strings.HasPrefix(r, "530"):
		fi.Auth = "denied"
	}
	_, _ = conn.Write([]byte("QUIT\r\n"))
	return fi
}

// ProbeDAV manda un PROPFIND al servidor web y avisa si respondió 207
// Multi-Status, o sea que WebDAV está habilitado. Devuelve también el
// cuerpo de la respuesta (el listado de archivos en XML) para el panel.
func ProbeDAV(conn net.Conn, host string) (bool, string) {
	req := fmt.Sprintf("PROPFIND / HTTP/1.1\r\nHost: %s\r\nDepth: 1\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", host, UserAgent)
	if _, err := conn.Write([]byte(req)); err != nil {
		return false, ""
	}
	data := sanitize(readBounded(conn, 16*1024))
	if strings.Contains(data, "207 Multi-Status") || strings.Contains(data, "HTTP/1.1 207") {
		return true, strings.TrimSpace(data)
	}
	return false, ""
}

// readBounded lee hasta limit bytes, parando en EOF, error o deadline.
func readBounded(conn net.Conn, limit int) string {
	br := bufio.NewReaderSize(conn, MaxRead)
	buf := make([]byte, MaxRead)
	var out []byte
	for len(out) < limit {
		n, err := br.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// sanitize elimina bytes de control y DEL conservando el texto UTF-8.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 32 && r != 127) || r == '\n' || r == '\t' || r == '\r' {
			return r
		}
		return -1
	}, s)
}

var pasvRe = regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)

// FTPList abre una sesión FTP anónima y devuelve los nombres de archivo
// del directorio actual. Fallo si el servidor no acepta anónimos o si
// no hay modo pasivo.
func FTPList(ip string, port int, timeout time.Duration) ([]string, error) {
	conn, err := DialTCP(net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	br := bufio.NewReader(conn)
	reply := func() string {
		line, _ := br.ReadString('\n')
		return strings.TrimSpace(line)
	}
	cmd := func(c string) string {
		_, _ = conn.Write([]byte(c + "\r\n"))
		return reply()
	}
	if l := reply(); !strings.HasPrefix(l, "220") {
		return nil, fmt.Errorf("banner inesperado: %s", l)
	}
	if l := cmd("USER anonymous"); !strings.HasPrefix(l, "331") && !strings.HasPrefix(l, "230") {
		return nil, fmt.Errorf("anónimo rechazado: %s", l)
	}
	if l := cmd("PASS anonymous@"); !strings.HasPrefix(l, "230") {
		return nil, fmt.Errorf("login denegado: %s", l)
	}
	_ = cmd("TYPE I")
	l := cmd("PASV")
	m := pasvRe.FindStringSubmatch(l)
	if !strings.HasPrefix(l, "227") || len(m) != 7 {
		return nil, fmt.Errorf("PASV no disponible: %s", l)
	}
	p1, _ := strconv.Atoi(m[5])
	p2, _ := strconv.Atoi(m[6])
	dataAddr := net.JoinHostPort(m[1]+"."+m[2]+"."+m[3]+"."+m[4], strconv.Itoa(p1*256+p2))
	dc, err := net.DialTimeout("tcp", dataAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("canal de datos PASV: %w", err)
	}
	defer dc.Close()
	_ = dc.SetDeadline(time.Now().Add(timeout))

	if l := cmd("LIST -la"); !strings.HasPrefix(l, "150") && !strings.HasPrefix(l, "125") {
		return nil, fmt.Errorf("LIST: %s", l)
	}
	data, err := io.ReadAll(io.LimitReader(dc, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("leyendo el listado: %w", err)
	}
	_ = cmd("QUIT")

	var files []string
	for _, ln := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimRight(ln, "\r"))
		if len(fields) >= 9 {
			files = append(files, fields[len(fields)-1])
		}
	}
	return files, nil
}

func parseHTTP(data string, info *Info) {
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		return
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "HTTP/") {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			info.StatusCode = code
		}
	}
	for _, line := range lines[1:] {
		if h := strings.SplitN(line, ":", 2); len(h) == 2 &&
			strings.EqualFold(strings.TrimSpace(h[0]), "server") {
			info.Server = strings.TrimSpace(h[1])
			break
		}
	}
	if m := titleRe.FindStringSubmatch(data); len(m) == 2 {
		info.Title = strings.TrimSpace(m[1])
	}
}
