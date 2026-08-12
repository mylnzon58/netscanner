// El comando netscanner es el punto de entrada del motor de
// descubrimiento de red.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"netscanner/pkg/banner"
	"netscanner/pkg/config"
	"netscanner/pkg/engine"
	"netscanner/pkg/exporter"
	"netscanner/pkg/geo"
	"netscanner/pkg/socks"
)

// resolveTarget convierte un hostname (o URL) en un CIDR /32 con la
// primera IPv4 que resuelva. Si la spec ya es un CIDR válido, no toca nada.
func resolveTarget(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if _, _, err := net.ParseCIDR(spec); err == nil {
		return spec, nil
	}
	host := strings.TrimPrefix(spec, "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return host + "/32", nil
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("no se pudo resolver %q: %w", spec, err)
	}
	for _, ip := range ips {
		if ip4 := net.ParseIP(ip).To4(); ip4 != nil {
			return ip4.String() + "/32", nil
		}
	}
	return "", fmt.Errorf("%q no resuelve a ninguna IPv4", spec)
}

func main() {
	opts, err := config.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	// -c acepta varios objetivos separados por coma o espacio; cada uno
	// puede ser una red, una IP o un dominio (se resuelve a /32).
	var cidrs []string
	for _, spec := range strings.FieldsFunc(opts.CIDR, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		cidr, err := resolveTarget(spec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
		cidrs = append(cidrs, cidr)
	}
	if len(cidrs) == 0 {
		fmt.Fprintln(os.Stderr, "error: falta el objetivo (-c)")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var totalJobs uint64
	for _, cidr := range cidrs {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			if hosts, err := engine.HostCount(ipnet); err == nil {
				totalJobs += hosts * uint64(len(opts.Ports))
			}
		}
	}
	if totalJobs > 1_000_000 {
		fmt.Fprintf(os.Stderr, "[aviso] se sondearán cerca de %d pares (ip,puerto)\n", totalJobs)
	}

	start := time.Now()
	fmt.Fprintf(os.Stderr, "[netscanner] objetivos=%d cidrs=%s ports=%v workers=%d timeout=%s\n",
		len(cidrs), strings.Join(cidrs, ","), opts.Ports, opts.Workers, opts.Timeout)

	if opts.Proxy != "" {
		proxy, err := socks.NewDialer(opts.Proxy, opts.Timeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
		engine.Dialer.Dial = proxy.Dial
		banner.DialTCP = func(addr string, timeout time.Duration) (net.Conn, error) {
			return proxy.Dial(addr)
		}
		fmt.Fprintf(os.Stderr, "[netscanner] anonimato: todas las conexiones via %s (tu IP real queda oculta)\n", proxy.URL())
	} else {
		fmt.Fprintln(os.Stderr, "[netscanner] aviso: escaneando con tu IP directa. Usa --proxy socks5://127.0.0.1:9050 (TOR) o una VPN para ocultarla.")
	}
	banner.UserAgent = opts.UserAgent

	db, err := geo.Open(opts.GeoIPPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[aviso] base GeoIP no disponible: %v (la geo quedará como Unknown)\n", err)
		db = geo.Unavailable()
	}
	defer db.Close()

	exp, err := exporter.NewWriter(opts.Output, 4096)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "[netscanner] escaneando (Ctrl+C detiene de forma prolija) ...")

	var final engine.Snapshot
	shared := &engine.Stats{}
	for _, cidr := range cidrs {
		opts.CIDR = cidr
		if _, err := engine.Run(ctx, opts, db, exp.Results(), shared); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
	final = shared.Snapshot()

	if err := exp.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "error al descargar la salida:", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n[listo] objetivos=%d intentos=%d abiertos=%d timeouts=%d errores=%d duración=%s salida=%s\n",
		len(cidrs), final.Attempts, final.Open, final.Timeout, final.Errored, time.Since(start).Round(time.Millisecond), opts.Output)
}
