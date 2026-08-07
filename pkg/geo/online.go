// Geolocalización online con el endpoint batch gratuito de ip-api.com.
// El plan free acepta hasta 100 direcciones por pedido y unos 45 pedidos
// por minuto, así que LookupOnline se autocontrola con una pausa entre
// lotes.
package geo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"time"
)

const (
	batchSize     = 100
	onlineTimeout = 10 * time.Second
	onlinePause   = 1500 * time.Millisecond
)

// OnlineInfo es una respuesta de geolocalización de ip-api.com.
type OnlineInfo struct {
	Status      string  `json:"status"`
	Message     string  `json:"message"`
	Query       string  `json:"query"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
}

// SampleBy24 reduce ips a una dirección representativa por bloque /24,
// descartando las privadas. Los representantes son estables (ordenados)
// así las corridas repetidas hacen las mismas consultas.
func SampleBy24(ips []string) []string {
	seen := make(map[uint32]bool)
	out := make([]string, 0, len(ips)/2)
	sort.Strings(ips)
	for _, s := range ips {
		ip := net.ParseIP(s).To4()
		if ip == nil || IsPrivate(ip) {
			continue
		}
		blk := uint32(ip[0])<<16 | uint32(ip[1])<<8 | uint32(ip[2])
		if seen[blk] {
			continue
		}
		seen[blk] = true
		out = append(out, s)
	}
	return out
}

// LookupOnline geolocaliza ips con el endpoint batch gratuito de
// ip-api.com. Devuelve un mapa con las direcciones consultadas; las que
// responden Status "fail" o sin coordenadas se omiten. Se mantiene una
// pausa entre pedidos para respetar el límite del plan free.
func LookupOnline(ips []string) (map[string]OnlineInfo, error) {
	infos := make(map[string]OnlineInfo)
	client := &http.Client{Timeout: onlineTimeout}
	for i := 0; i < len(ips); i += batchSize {
		end := i + batchSize
		if end > len(ips) {
			end = len(ips)
		}
		part := make([]map[string]string, 0, end-i)
		for _, ip := range ips[i:end] {
			part = append(part, map[string]string{"query": ip})
		}
		got, err := postBatch(client, part)
		if err != nil {
			return nil, err
		}
		for _, g := range got {
			if g.Status != "success" || g.Lat == 0 && g.Lon == 0 {
				continue
			}
			infos[g.Query] = g
		}
		if end < len(ips) {
			time.Sleep(onlinePause)
		}
	}
	return infos, nil
}

// LookupMyIP resuelve la dirección pública del propio equipo con el
// endpoint json de ip-api.com; sirve para identificar el ISP local.
func LookupMyIP() (OnlineInfo, error) {
	client := &http.Client{Timeout: onlineTimeout}
	resp, err := client.Get("http://ip-api.com/json/")
	if err != nil {
		return OnlineInfo{}, fmt.Errorf("ip-api: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return OnlineInfo{}, err
	}
	var g OnlineInfo
	if err := json.Unmarshal(body, &g); err != nil {
		return OnlineInfo{}, err
	}
	return g, nil
}

func postBatch(client *http.Client, part []map[string]string) ([]OnlineInfo, error) {
	payload, err := json.Marshal(part)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := client.Post("http://ip-api.com/batch", "application/json", bytes.NewReader(payload))
		if err != nil {
			if attempt == 1 {
				return nil, err
			}
			time.Sleep(onlinePause)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			var out []OnlineInfo
			if err := json.Unmarshal(body, &out); err != nil {
				return nil, err
			}
			return out, nil
		}
		if attempt == 1 {
			return nil, fmt.Errorf("ip-api respondió %d: %s", resp.StatusCode, body)
		}
		time.Sleep(onlinePause)
	}
	return nil, fmt.Errorf("ip-api no responde")
}
