package lat_test

import (
	"fmt"
	"testing"

	"github.com/sHesl/scratchpad/lat"
)

func TestT(t *testing.T) {
	badSBox := func(b byte) byte {
		b += 16
		if b > 255 {
			b -= 255
		}
		return b
	}

	r := lat.LinearApproximationTable(badSBox)

	total := float32(0)
	for m, a := range r {
		fmt.Printf("mask %08b = %f%%\n", m, a)
		total += a
	}

	fmt.Printf("total = %f", total/float32(len(r)))
}
