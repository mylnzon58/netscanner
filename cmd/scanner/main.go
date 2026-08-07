// Command netscanner is the entrypoint of the network discovery engine.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netscanner/pkg/banner"
	"netscanner/pkg/config"
	"netscanner/pkg/engine"
	"netscanner/pkg/exporter"
	"netscanner/pkg/geo"
	"netscanner/pkg/socks"
)

func main() {
	opts, err := config.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, ipnet, _ := net.ParseCIDR(opts.CIDR)
	if hosts, err := engine.HostCount(ipnet); err == nil {
		if total := hosts * uint64(len(opts.Ports)); total > 1_000_000 {
			fmt.Fprintf(os.Stderr, "[warn] %s will probe about %d (ip,port) pairs\n", opts.CIDR, total)
		}
	}

	start := time.Now()
	fmt.Fprintf(os.Stderr, "[netscanner] cidr=%s ports=%v workers=%d timeout=%s\n",
		opts.CIDR, opts.Ports, opts.Workers, opts.Timeout)

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
		fmt.Fprintf(os.Stderr, "[warn] GeoIP database unavailable: %v (geo will be Unknown)\n", err)
		db = geo.Unavailable()
	}
	defer db.Close()

	exp, err := exporter.NewWriter(opts.Output, 4096)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "[netscanner] scanning (Ctrl+C stops gracefully) ...")

	stats, err := engine.Run(ctx, opts, db, exp.Results())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if err := exp.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "error flushing output:", err)
		os.Exit(1)
	}

	s := stats.Snapshot()
	fmt.Fprintf(os.Stderr, "\n[done] attempts=%d open=%d timeouts=%d errors=%d duration=%s output=%s\n",
		s.Attempts, s.Open, s.Timeout, s.Errored, time.Since(start).Round(time.Millisecond), opts.Output)
}
