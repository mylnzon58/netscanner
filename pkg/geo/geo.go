// Package geo resuelve la ubicación geográfica de direcciones IPv4
// públicas usando la base local MaxMind GeoLite2 City (.mmdb).
package geo

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// Location es el enriquecimiento geográfico pegado a un resultado.
type Location struct {
	Label     string
	Country   string
	City      string
	Latitude  float64
	Longitude float64
}

// GeoDB envuelve el lector de MaxMind. Un lector nulo significa que la
// base no está disponible y toda consulta devuelve Unknown.
type GeoDB struct {
	reader *geoip2.Reader
}

// Open carga la base .mmdb en path. Si el archivo no se puede leer se
// devuelve un error y los llamadores pueden usar Unavailable.
func Open(path string) (*GeoDB, error) {
	r, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("abriendo %s: %w", path, err)
	}
	return &GeoDB{reader: r}, nil
}

// Unavailable devuelve un GeoDB que reporta Unknown para todas las
// direcciones; se usa cuando no hay archivo de base.
func Unavailable() *GeoDB { return &GeoDB{} }

// Close libera el archivo de base subyacente.
func (g *GeoDB) Close() error {
	if g == nil || g.reader == nil {
		return nil
	}
	return g.reader.Close()
}

// Lookup resuelve ip a una Location. Las direcciones privadas se
// etiquetan como Internal/Private sin consultar la base; las públicas se
// resuelven contra el .mmdb local; todo lo demás es Unknown.
func (g *GeoDB) Lookup(ip net.IP) Location {
	ip4 := ip.To4()
	if ip4 != nil && IsPrivate(ip4) {
		return Location{Label: "Internal/Private"}
	}
	if g == nil || g.reader == nil {
		return Location{Label: "Unknown"}
	}
	rec, err := g.reader.City(ip)
	if err != nil {
		return Location{Label: "Unknown"}
	}
	country := rec.Country.Names["en"]
	if country == "" {
		country = rec.Country.IsoCode
	}
	return Location{
		Label:     "Public",
		Country:   country,
		City:      rec.City.Names["en"],
		Latitude:  rec.Location.Latitude,
		Longitude: rec.Location.Longitude,
	}
}

// IsPrivate indica si ip pertenece a un rango IPv4 privado o de uso
// especial: RFC 1918, loopback y link-local.
func IsPrivate(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168) ||
		ip4[0] == 127 ||
		(ip4[0] == 169 && ip4[1] == 254)
}
