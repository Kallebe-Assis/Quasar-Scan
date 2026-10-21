// genoui baixa a base oficial de fabricantes (OUI) do IEEE e gera o arquivo
// compactado que é embutido no executável, permitindo identificar fabricantes
// sem internet. Rodar apenas quando quiser atualizar a base:
//
//	go run ./tools/genoui
package main

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	sourceURL = "https://standards-oui.ieee.org/oui/oui.csv"
	outFile   = "internal/oui/oui.txt.gz"
)

func main() {
	var src io.Reader
	if len(os.Args) > 1 {
		// Permite usar um CSV já baixado: go run ./tools/genoui caminho/oui.csv
		f, err := os.Open(os.Args[1])
		check(err)
		defer f.Close()
		src = f
	} else {
		client := &http.Client{Timeout: 60 * time.Second}
		req, _ := http.NewRequest("GET", sourceURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (quasar-scan genoui)")
		resp, err := client.Do(req)
		check(err)
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			check(fmt.Errorf("download falhou: %s", resp.Status))
		}
		src = resp.Body
	}

	r := csv.NewReader(src)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	check(err)

	vendors := map[string]string{}
	for _, row := range rows[1:] {
		if len(row) < 3 || len(row[1]) != 6 {
			continue
		}
		name := strings.Join(strings.Fields(row[2]), " ")
		vendors[strings.ToUpper(row[1])] = name
	}

	keys := make([]string, 0, len(vendors))
	for k := range vendors {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out, err := os.Create(outFile)
	check(err)
	defer out.Close()
	gz, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	for _, k := range keys {
		fmt.Fprintf(gz, "%s\t%s\n", k, vendors[k])
	}
	check(gz.Close())
	fmt.Printf("%d fabricantes gravados em %s\n", len(keys), outFile)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}
