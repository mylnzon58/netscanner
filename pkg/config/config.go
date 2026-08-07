// Package config parses and validates the netscanner command-line flags.
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

// Options holds the validated runtime configuration of the scanner.
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

// Parse reads the CLI flags from args (excluding the program name),
// validates them and returns the resulting Options.
func Parse(args []string) (*Options, error) {
	opts := &Options{}

	fs := flag.NewFlagSet("netscanner", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&opts.CIDR, "cidr", DefaultCIDR, "CIDR range to scan (IPv4), e.g. 192.168.1.0/24")
	fs.StringVar(&opts.CIDR, "c", DefaultCIDR, "shorthand for --cidr")
	fs.StringVar(&opts.PortsRaw, "ports", DefaultPorts, "comma-separated TCP ports, e.g. 80,443")
	fs.StringVar(&opts.PortsRaw, "p", DefaultPorts, "shorthand for --ports")
	fs.IntVar(&opts.Workers, "workers", DefaultWorkers, "maximum number of concurrent connections")
	fs.IntVar(&opts.Workers, "w", DefaultWorkers, "shorthand for --workers")
	fs.IntVar(&opts.TimeoutMS, "timeout", DefaultTimeoutMS, "connection timeout in milliseconds")
	fs.IntVar(&opts.TimeoutMS, "t", DefaultTimeoutMS, "shorthand for --timeout")
	fs.StringVar(&opts.GeoIPPath, "geoip", DefaultGeoIPPath, "path to the GeoLite2 City .mmdb database")
	fs.StringVar(&opts.GeoIPPath, "g", DefaultGeoIPPath, "shorthand for --geoip")
	fs.StringVar(&opts.Output, "output", DefaultOutput, "path of the JSONL output file")
	fs.StringVar(&opts.Output, "o", DefaultOutput, "shorthand for --output")
	fs.IntVar(&opts.MaxBodyKB, "max-body", DefaultMaxBodyKB, "max HTTP body captured per web port, in KiB (0 disables)")
	fs.StringVar(&opts.StatsFile, "stats", DefaultStatsFile, "write live scan progress to this JSON file (for the dashboard)")
	fs.StringVar(&opts.FTPPortsRaw, "ftp-ports", DefaultFTPPorts, "ports that get an anonymous FTP login probe")
	fs.BoolVar(&opts.DAV, "dav", DefaultDAV, "probe web ports with PROPFIND to detect WebDAV shares")
	fs.StringVar(&opts.Proxy, "proxy", "", "route every connection through a SOCKS5 proxy, e.g. socks5://127.0.0.1:9050 (TOR)")
	fs.StringVar(&opts.UserAgent, "user-agent", DefaultUserAgent, "HTTP User-Agent sent in the probes")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "netscanner - high performance TCP network discovery engine\n\n")
		fmt.Fprintf(fs.Output(), "Usage: netscanner [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	return opts, nil
}

func (o *Options) validate() error {
	_, ipnet, err := net.ParseCIDR(o.CIDR)
	if err != nil {
		return fmt.Errorf("invalid --cidr %q: %w", o.CIDR, err)
	}
	if ipnet.IP.To4() == nil {
		return fmt.Errorf("invalid --cidr %q: only IPv4 networks are supported", o.CIDR)
	}

	ports, err := parsePorts(o.PortsRaw)
	if err != nil {
		return err
	}
	o.Ports = ports

	if o.Workers < 1 || o.Workers > 1<<16 {
		return fmt.Errorf("invalid --workers %d: must be between 1 and 65536", o.Workers)
	}
	if o.TimeoutMS < 10 || o.TimeoutMS > 5*60*1000 {
		return fmt.Errorf("invalid --timeout %d: must be between 10 and 300000 ms", o.TimeoutMS)
	}
	o.Timeout = time.Duration(o.TimeoutMS) * time.Millisecond

	if o.MaxBodyKB < 0 || o.MaxBodyKB > 512 {
		return fmt.Errorf("invalid --max-body %d: must be between 0 and 512 KiB", o.MaxBodyKB)
	}
	o.MaxBodyBytes = o.MaxBodyKB * 1024

	if strings.TrimSpace(o.FTPPortsRaw) == "" {
		return fmt.Errorf("invalid --ftp-ports: must not be empty")
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

// parsePorts splits, validates, deduplicates and sorts a port list.
func parsePorts(raw string) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("invalid --ports: must not be empty")
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
			return nil, fmt.Errorf("invalid port %q: must be an integer between 1 and 65535", s)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid --ports: must not be empty")
	}
	sort.Ints(out)
	return out, nil
}
