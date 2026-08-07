// Clasificación de infraestructura: detecta si una IP pertenece a un
// CDN o proveedor de cloud conocido, con una tabla local de rangos.
package geo

import (
	"net"
	"sync"
)

type cdnEntry struct {
	net  *net.IPNet
	name string
}

var (
	cdnOnce sync.Once
	cdnList []cdnEntry
)

// rangos conocidos de CDN y cloud, resumidos a los bloques más comunes.
var cdnRanges = []struct {
	cidr string
	name string
}{
	{"104.16.0.0/13", "Cloudflare"},
	{"104.24.0.0/14", "Cloudflare"},
	{"103.21.244.0/22", "Cloudflare"},
	{"103.22.200.0/22", "Cloudflare"},
	{"103.31.4.0/22", "Cloudflare"},
	{"141.101.64.0/18", "Cloudflare"},
	{"108.162.192.0/18", "Cloudflare"},
	{"190.93.240.0/20", "Cloudflare"},
	{"188.114.96.0/20", "Cloudflare"},
	{"197.234.240.0/22", "Cloudflare"},
	{"198.41.128.0/17", "Cloudflare"},
	{"162.158.0.0/15", "Cloudflare"},
	{"131.0.72.0/22", "Cloudflare"},
	{"172.64.0.0/13", "Cloudflare"},
	{"173.245.48.0/20", "Cloudflare"},
	{"142.250.0.0/15", "Google"},
	{"172.217.0.0/16", "Google"},
	{"216.58.192.0/19", "Google"},
	{"74.125.0.0/16", "Google"},
	{"64.233.160.0/19", "Google"},
	{"13.32.0.0/15", "Amazon AWS"},
	{"13.224.0.0/14", "Amazon AWS"},
	{"52.84.0.0/15", "Amazon AWS"},
	{"54.230.0.0/16", "Amazon AWS"},
	{"99.84.0.0/16", "Amazon AWS"},
	{"205.251.192.0/19", "Amazon AWS"},
	{"3.160.0.0/12", "Amazon AWS"},
	{"23.32.0.0/11", "Akamai"},
	{"23.192.0.0/11", "Akamai"},
	{"96.6.0.0/15", "Akamai"},
	{"104.64.0.0/10", "Akamai"},
	{"184.24.0.0/13", "Akamai"},
	{"151.101.0.0/16", "Fastly"},
	{"199.232.0.0/16", "Fastly"},
	{"146.75.0.0/16", "Fastly"},
	{"20.0.0.0/8", "Microsoft/Azure"},
	{"40.0.0.0/10", "Microsoft/Azure"},
	{"13.64.0.0/11", "Microsoft/Azure"},
	{"157.240.0.0/16", "Meta"},
	{"31.13.24.0/21", "Meta"},
	{"51.68.0.0/15", "OVH"},
	{"137.74.0.0/16", "OVH"},
	{"51.75.0.0/16", "OVH"},
	{"145.239.0.0/16", "OVH"},
	{"104.248.0.0/20", "DigitalOcean"},
	{"138.197.0.0/16", "DigitalOcean"},
	{"159.203.0.0/16", "DigitalOcean"},
	{"167.71.0.0/16", "DigitalOcean"},
	{"76.76.21.0/24", "Vercel"},
	{"13.248.0.0/14", "Vercel"},
	{"75.2.0.0/16", "Netlify"},
	{"54.155.0.0/16", "Netlify"},
	{"185.199.108.0/22", "GitHub Pages"},
	{"82.223.0.0/16", "Hostinger"},
	{"145.14.0.0/16", "Hostinger"},
	{"84.247.0.0/16", "Hostinger"},
}

func initCDN() {
	for _, r := range cdnRanges {
		if _, ipnet, err := net.ParseCIDR(r.cidr); err == nil {
			cdnList = append(cdnList, cdnEntry{net: ipnet, name: r.name})
		}
	}
}

// ClassifyIP devuelve el nombre del CDN o proveedor de cloud al que
// pertenece la IP, o "" si no está en la tabla local.
func ClassifyIP(ip string) string {
	cdnOnce.Do(initCDN)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	for _, e := range cdnList {
		if e.net.Contains(parsed) {
			return e.name
		}
	}
	return ""
}
