// genicon gera o ícone do aplicativo recortando o emblema do logo (assets/logo.png)
// e arredondando os cantos. O resultado (assets/icon.png) é usado pelo go-winres
// e pela interface:
//
//	go run ./tools/genicon
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"

	"golang.org/x/image/draw"
)

const (
	size   = 256
	radius = 48
)

// emblem é a área do emblema circular dentro do logo de 1024x572.
var emblem = image.Rect(94, 132, 396, 434)

func main() {
	f, err := os.Open("assets/logo.png")
	check(err)
	logo, err := png.Decode(f)
	f.Close()
	check(err)

	scaled := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.CatmullRom.Scale(scaled, scaled.Bounds(), logo, emblem, draw.Src, nil)

	// Cantos arredondados com antialiasing.
	out := image.NewRGBA(scaled.Bounds())
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			a := coverage(float64(x)+0.5, float64(y)+0.5)
			if a == 0 {
				continue
			}
			c := scaled.RGBAAt(x, y)
			out.SetRGBA(x, y, color.RGBA{uint8(float64(c.R) * a), uint8(float64(c.G) * a), uint8(float64(c.B) * a), uint8(255 * a)})
		}
	}

	o, err := os.Create("assets/icon.png")
	check(err)
	defer o.Close()
	check(png.Encode(o, out))
	fmt.Println("assets/icon.png gerado a partir de assets/logo.png")
}

// coverage devolve quanto do pixel está dentro do quadrado de cantos arredondados.
func coverage(x, y float64) float64 {
	cx := math.Max(radius, math.Min(x, size-radius))
	cy := math.Max(radius, math.Min(y, size-radius))
	d := math.Hypot(x-cx, y-cy)
	return math.Max(0, math.Min(1, radius-d+0.5))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}
