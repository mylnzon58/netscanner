// Package config se encarga de leer y validar los flags de netscanner.
package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultCIDR      = "192.168.1.0/24"
	DefaultPorts     = "80,443,8080,8000,554,21,22"
	DefaultWorkers   = 500
	DefaultTimeoutMS = 2000
	DefaultGeoIPPath = "./GeoLite2-City.mmdb"
	DefaultOutput    = "results.jsonl"
	DefaultMaxBodyKB = 16
	DefaultStatsFile = ""
	DefaultFTPPorts  = "21"
	DefaultDAV       = true
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

// Options guarda la configuración ya validada del escáner.
type Options struct {
	CIDR         string
	PortsRaw     string
	Ports        []int
	Workers      int
	TimeoutMS    int
	Timeout      time.Duration
	GeoIPPath    string
	Output       string
	MaxBodyKB    int
	MaxBodyBytes int
	StatsFile    string
	FTPPortsRaw  string
	FTPPorts     []int
	DAV          bool
	Proxy        string
	UserAgent    string
}

// Parse lee los flags de args (sin el nombre del programa), los valida
// y devuelve las Options resultantes.
func Parse(args []string) (*Options, error) {
	opts := &Options{}

	fs := flag.NewFlagSet("netscanner", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&opts.CIDR, "cidr", DefaultCIDR, "rango CIDR a escanear (IPv4), p.ej. 192.168.1.0/24")
	fs.StringVar(&opts.CIDR, "c", DefaultCIDR, "abreviatura de --cidr")
	fs.StringVar(&opts.PortsRaw, "ports", DefaultPorts, "puertos TCP separados por coma, p.ej. 80,443")
	fs.StringVar(&opts.PortsRaw, "p", DefaultPorts, "abreviatura de --ports")
	fs.IntVar(&opts.Workers, "workers", DefaultWorkers, "máximo de conexiones en paralelo")
	fs.IntVar(&opts.Workers, "w", DefaultWorkers, "abreviatura de --workers")
	fs.IntVar(&opts.TimeoutMS, "timeout", DefaultTimeoutMS, "timeout de conexión en milisegundos")
	fs.IntVar(&opts.TimeoutMS, "t", DefaultTimeoutMS, "abreviatura de --timeout")
	fs.StringVar(&opts.GeoIPPath, "geoip", DefaultGeoIPPath, "ruta a la base GeoLite2 City .mmdb")
	fs.StringVar(&opts.GeoIPPath, "g", DefaultGeoIPPath, "abreviatura de --geoip")
	fs.StringVar(&opts.Output, "output", DefaultOutput, "ruta del archivo JSONL de salida")
	fs.StringVar(&opts.Output, "o", DefaultOutput, "abreviatura de --output")
	fs.IntVar(&opts.MaxBodyKB, "max-body", DefaultMaxBodyKB, "máximo del cuerpo HTTP capturado por puerto web, en KiB (0 lo desactiva)")
	fs.StringVar(&opts.StatsFile, "stats", DefaultStatsFile, "escribir el progreso en vivo a este JSON (para el dashboard)")
	fs.StringVar(&opts.FTPPortsRaw, "ftp-ports", DefaultFTPPorts, "puertos que reciben sondeo de login FTP anónimo")
	fs.BoolVar(&opts.DAV, "dav", DefaultDAV, "sondear puertos web con PROPFIND para detectar WebDAV")
	fs.StringVar(&opts.Proxy, "proxy", "", "mandar todas las conexiones por un proxy SOCKS5, p.ej. socks5://127.0.0.1:9050 (TOR)")
	fs.StringVar(&opts.UserAgent, "user-agent", DefaultUserAgent, "User-Agent HTTP que mandan los sondeos")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "netscanner - motor de descubrimiento de red TCP de alto rendimiento\n\n")
		fmt.Fprintf(fs.Output(), "Uso: netscanner [opciones]\n\nOpciones:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("argumentos posicionales inesperados: %v", fs.Args())
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	return opts, nil
}

func (o *Options) validate() error {
	_, ipnet, err := net.ParseCIDR(o.CIDR)
	if err != nil {
		return fmt.Errorf("--cidr inválido %q: %w", o.CIDR, err)
	}
	if ipnet.IP.To4() == nil {
		return fmt.Errorf("--cidr inválido %q: solo se soportan redes IPv4", o.CIDR)
	}

	ports, err := parsePorts(o.PortsRaw)
	if err != nil {
		return err
	}
	o.Ports = ports

	if o.Workers < 1 || o.Workers > 1<<16 {
		return fmt.Errorf("--workers inválido %d: debe estar entre 1 y 65536", o.Workers)
	}
	if o.TimeoutMS < 10 || o.TimeoutMS > 5*60*1000 {
		return fmt.Errorf("--timeout inválido %d: debe estar entre 10 y 300000 ms", o.TimeoutMS)
	}
	o.Timeout = time.Duration(o.TimeoutMS) * time.Millisecond

	if o.MaxBodyKB < 0 || o.MaxBodyKB > 512 {
		return fmt.Errorf("--max-body inválido %d: debe estar entre 0 y 512 KiB", o.MaxBodyKB)
	}
	o.MaxBodyBytes = o.MaxBodyKB * 1024

	if strings.TrimSpace(o.FTPPortsRaw) == "" {
		return fmt.Errorf("--ftp-ports inválido: no puede estar vacío")
	}
	ftp, err := parsePorts(o.FTPPortsRaw)
	if err != nil {
		return err
	}
	o.FTPPorts = ftp

	if o.UserAgent == "" {
		o.UserAgent = DefaultUserAgent
	}
	return nil
}

// parsePorts separa, valida, elimina duplicados y ordena una lista de
// puertos escrita como texto.
func parsePorts(raw string) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("--ports inválido: no puede estar vacío")
	}
	seen := make(map[int]bool)
	var out []int
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("puerto inválido %q: debe ser un entero entre 1 y 65535", s)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--ports inválido: no puede estar vacío")
	}
	sort.Ints(out)
	return out, nil
}
