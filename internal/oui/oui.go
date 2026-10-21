// Package oui identifica o fabricante de um dispositivo pelo prefixo do MAC.
// A base vem embutida no executável (gerada por tools/genoui), então funciona offline.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strings"
	"sync"
)

//go:embed oui.txt.gz
var data []byte

var (
	once    sync.Once
	vendors map[string]string
)

func load() {
	vendors = make(map[string]string, 45000)
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return
	}
	sc := bufio.NewScanner(gz)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "\t"); ok {
			vendors[k] = v
		}
	}
}

// Lookup devolve o fabricante do MAC, ou "" se desconhecido.
func Lookup(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	once.Do(load)
	key := strings.ToUpper(strings.ReplaceAll(mac[:3].String(), ":", ""))
	return vendors[key]
}

// IsRandomized indica MAC "localmente administrado" — típico de celulares
// com MAC aleatório (privacidade), VMs e alguns equipamentos virtuais.
func IsRandomized(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&0x02 != 0
}
