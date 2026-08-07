// Package geo resolves the geographical location of public IPv4
// addresses using a local MaxMind GeoLite2 City database (.mmdb).
package geo

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// Location is the geographic enrichment attached to a scan result.
type Location struct {
	Label     string
	Country   string
	City      string
	Latitude  float64
	Longitude float64
}

// GeoDB wraps the MaxMind reader. A nil reader means the database is
// unavailable and every lookup returns the Unknown location.
type GeoDB struct {
	reader *geoip2.Reader
}

// Open loads the .mmdb database at path. When the file cannot be read
// an error is returned and callers can fall back to Unavailable.
func Open(path string) (*GeoDB, error) {
	r, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return &GeoDB{reader: r}, nil
}

// Unavailable returns a GeoDB that reports Unknown for every address,
// used when no database file is present.
func Unavailable() *GeoDB { return &GeoDB{} }

// Close releases the underlying database file.
func (g *GeoDB) Close() error {
	if g == nil || g.reader == nil {
		return nil
	}
	return g.reader.Close()
}

// Lookup resolves ip to a Location. Private addresses are labelled
// Internal/Private without querying the database; public addresses are
// resolved against the local .mmdb; anything else is Unknown.
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

// IsPrivate reports whether ip belongs to a private or special-purpose
// IPv4 range: RFC 1918, loopback and link-local.
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
