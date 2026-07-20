// Package entropy computes Shannon entropy, used to spot packed or encrypted
// data (compressed/encrypted content approaches the 8.0 bits/byte ceiling).
package entropy

import "math"

// Shannon returns the entropy of data in bits per byte, 0..8.
// Plain English/source hovers around 4–5; encrypted or compressed data is >7.5.
func Shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
