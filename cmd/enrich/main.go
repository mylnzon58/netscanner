// El comando enrich geolocaliza las IPs de un archivo JSONL de
// resultados ya existente usando el servicio gratuito de ip-api.com
// (muestreado a una dirección por /24) y escribe un archivo JSONL nuevo
// con las coordenadas y los campos de ISP completados. El archivo
// original nunca se modifica.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"netscanner/pkg/exporter"
	"netscanner/pkg/geo"
)

type record struct {
	Timestamp string          `json:"timestamp"`
	IP        string          `json:"ip"`
	Port      int             `json:"port"`
	Status    string          `json:"status"`
	Banner    exporter.Banner `json:"banner"`
	Geo       exporter.Geo    `json:"geo"`
}

func main() {
	in := flag.String("in", "proveedor.jsonl", "archivo JSONL de resultados de entrada")
	out := flag.String("out", "", "archivo JSONL de salida (por defecto: <in> sin extensión + _geo.jsonl)")
	sample := flag.Bool("sample", true, "consultar solo una IP por bloque /24")
	flag.Parse()

	if *out == "" {
		*out = strings.TrimSuffix(*in, ".jsonl") + "_geo.jsonl"
	}

	recs, unique, err := readRecords(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("[enrich] %d registros, %d IPs públicas únicas\n", len(recs), len(unique))

	toQuery := make([]string, 0, len(unique))
	for ip := range unique {
		toQuery = append(toQuery, ip)
	}
	if *sample {
		toQuery = geo.SampleBy24(toQuery)
		fmt.Printf("[enrich] muestreo por /24: %d direcciones a consultar\n", len(toQuery))
	}

	start := time.Now()
	infos, err := geo.LookupOnline(toQuery)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("[enrich] %d/%d geolocalizadas en %s\n", len(infos), len(toQuery), time.Since(start).Round(time.Second))

	found := 0
	blockInfo := make(map[string]geo.OnlineInfo)
	for ip, info := range infos {
		blockInfo[blockOf(ip)] = info
	}

	of, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer of.Close()
	bw := bufio.NewWriterSize(of, 64*1024)
	defer bw.Flush()
	enc := json.NewEncoder(bw)

	asn := parseASN(infos)
	for _, r := range recs {
		info, ok := blockInfo[blockOf(r.IP)]
		if ok {
			r.Geo = exporter.Geo{
				Label:     "Public",
				Country:   info.Country,
				City:      info.City,
				Latitude:  info.Lat,
				Longitude: info.Lon,
				ISP:       info.ISP,
				ASN:       asn,
				Org:       info.Org,
			}
			found++
		}
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}

	cities := map[string]int{}
	for _, info := range infos {
		if info.City != "" {
			cities[info.City]++
		}
	}
	fmt.Printf("[enrich] se escribió %s (%d registros enriquecidos)\n", *out, found)
	fmt.Printf("[enrich] ciudades: %s\n", topCities(cities))
}

func readRecords(path string) ([]record, map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	recs := make([]record, 0, 4096)
	unique := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, nil, fmt.Errorf("línea %q: %w", first80(line), err)
		}
		if ip := net.ParseIP(r.IP); ip != nil && !geo.IsPrivate(ip.To4()) {
			unique[r.IP] = true
		}
		recs = append(recs, r)
	}
	return recs, unique, sc.Err()
}

func blockOf(ip string) string {
	ip4 := net.ParseIP(ip).To4()
	if ip4 == nil {
		return ip
	}
	return fmt.Sprintf("%d.%d.%d.0", ip4[0], ip4[1], ip4[2])
}

func parseASN(infos map[string]geo.OnlineInfo) string {
	seen := map[string]int{}
	for _, info := range infos {
		if info.AS != "" {
			seen[info.AS]++
		}
	}
	best, n := "", 0
	for as, c := range seen {
		if c > n {
			best, n = as, c
		}
	}
	return best
}

func topCities(m map[string]int) string {
	names := make([]string, 0, len(m))
	for c, n := range m {
		names = append(names, fmt.Sprintf("%s x%d", c, n))
	}
	if len(names) == 0 {
		return "ninguna"
	}
	return strings.Join(names, ", ")
}

func first80(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}
