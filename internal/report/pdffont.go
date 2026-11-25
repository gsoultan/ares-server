// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package report

import "strings"

// Advance widths, in 1/1000 em, of the printable ASCII range (0x20-0x7e) in
// the standard Helvetica and Helvetica-Bold fonts (from their Adobe AFM files,
// WinAnsiEncoding, which the writer declares). Every PDF reader ships these fonts, so the report stays
// self-contained while reading as a proportional, client-ready document; the
// table lets the writer wrap lines exactly without embedding a font.
var helveticaWidths = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // space ! " # $ % & ' ( ) * + , - . /
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, // 0-9
	278, 278, 584, 584, 584, 556, 1015, // : ; < = > ? @
	667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, // A-M
	722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, // N-Z
	278, 278, 278, 469, 556, 333, // [ \ ] ^ _ `
	556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, // a-m
	556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, // n-z
	334, 260, 334, 584, // { | } ~
}

var helveticaBoldWidths = [95]int{
	278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
	333, 333, 584, 584, 584, 611, 975,
	722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833,
	722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611,
	333, 278, 333, 584, 556, 333,
	556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889,
	611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500,
	389, 280, 389, 584,
}

// textWidth is the width in points of s set in font at size, measured after the
// same ASCII transliteration the content stream applies.
func textWidth(font string, size float64, s string) float64 {
	plain := pdfASCII(s)
	if font == fontCode {
		return float64(len(plain)) * size * 0.6 // Courier is monospaced
	}
	table := &helveticaWidths
	if font == fontBold {
		table = &helveticaBoldWidths
	}
	total := 0
	for i := 0; i < len(plain); i++ {
		c := plain[i]
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		total += table[c-0x20]
	}
	return float64(total) * size / 1000
}

// wrapWidth breaks s into lines no wider than maxW points, preferring to break
// on spaces and hard-splitting any single word wider than the line.
func wrapWidth(s string, maxW float64, measure func(string) float64) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var out []string
	cur := ""
	for _, w := range words {
		for measure(w) > maxW && len(w) > 1 {
			// Hard-split an over-long token (a URL or hash) at the widest prefix that fits.
			n := len(w) - 1
			for n > 1 && measure(w[:n]) > maxW {
				n--
			}
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			out = append(out, w[:n])
			w = w[n:]
		}
		switch {
		case cur == "":
			cur = w
		case measure(cur+" "+w) <= maxW:
			cur += " " + w
		default:
			out = append(out, cur)
			cur = w
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
