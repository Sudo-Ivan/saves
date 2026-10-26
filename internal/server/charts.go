// SPDX-License-Identifier: 0BSD

package server

import (
	"math"
	"strconv"
	"strings"
)

// ChartPoint is one plotted coordinate.
type ChartPoint struct{ X, Y float64 }

// Axis is a tick with its SVG coordinate.
type Axis struct {
	Label string
	Pos   float64
}

// LineChart is SVG geometry for a line with area fill.
type LineChart struct {
	W, H           int
	Points         string
	Area           string
	YTicks, XTicks []Axis
	Max            float64
	Empty          bool
}

// BarChart is SVG geometry for bars.
type BarChart struct {
	W, H           int
	Bars           []BarRect
	YTicks, XTicks []Axis
	Max            float64
	Empty          bool
}

// BarRect is one bar.
type BarRect struct {
	X, Y, W, H int
	Label      string
	Value      float64
}

const (
	cLeft   = 44.0
	cRight  = 6.0
	cTop    = 6.0
	cBottom = 18.0
)

func clampWH(w, h int) (float64, float64) {
	if w < 120 {
		w = 120
	}
	if h < 40 {
		h = 40
	}
	return float64(w), float64(h)
}

// niceMax rounds up to 1, 2, 2.5 or 5 times a power of ten.
func niceMax(v float64) float64 {
	if v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return 1
	}
	exp := math.Floor(math.Log10(v))
	base := math.Pow(10, exp)
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if v <= m*base {
			return m * base
		}
	}
	return 10 * base
}

func f1(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		v = 0
	}
	return strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64)
}

func f1d(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		v = 0
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// thinLabels returns at most max labels at even positions.
func thinLabels(labels []string) []string {
	if len(labels) <= 6 {
		return labels
	}
	out := make([]string, len(labels))
	step := float64(len(labels)-1) / 5
	last := -1
	for i := 0; i < 6; i++ {
		idx := int(math.Round(float64(i) * step))
		if idx >= len(labels) {
			idx = len(labels) - 1
		}
		if idx != last {
			out[idx] = labels[idx]
			last = idx
		}
	}
	return out
}

func scale(vals []float64, w, h float64) ([]ChartPoint, float64) {
	var max float64
	for _, v := range vals {
		if v < 0 {
			v = 0
		}
		if v > max {
			max = v
		}
	}
	max = niceMax(max)
	pw, ph := w-cLeft-cRight, h-cTop-cBottom
	pts := make([]ChartPoint, len(vals))
	n := len(vals)
	for i, v := range vals {
		if v < 0 {
			v = 0
		}
		x := cLeft
		if n > 1 {
			x = cLeft + pw*float64(i)/float64(n-1)
		}
		y := cTop + ph - ph*(v/max)
		pts[i] = ChartPoint{x, y}
	}
	return pts, max
}

// NewLineChart builds line geometry for vals.
func NewLineChart(vals []float64, xlabels []string, w, h int, fmt func(float64) string) LineChart {
	wf, hf := clampWH(w, h)
	lc := LineChart{W: int(wf), H: int(hf)}
	if len(vals) == 0 {
		lc.Empty = true
		return lc
	}
	allZero := true
	for _, v := range vals {
		if v > 0 {
			allZero = false
			break
		}
	}
	pts, max := scale(vals, wf, hf)
	lc.Max = max
	if allZero {
		lc.Empty = true
	}
	if len(vals) == 1 {
		p := pts[0]
		lc.Points = f1(p.X-2) + "," + f1(p.Y) + " " + f1(p.X+2) + "," + f1(p.Y)
	} else {
		var sb strings.Builder
		for i, p := range pts {
			if i > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(f1(p.X) + "," + f1d(p.Y))
		}
		lc.Points = sb.String()
	}
	base := hf - cBottom
	lc.Area = "M" + f1(pts[0].X) + "," + f1(base) + " L" + lc.Points + " L" + f1(pts[len(pts)-1].X) + "," + f1(base) + " Z"
	ph := hf - cTop - cBottom
	for i := 0; i <= 3; i++ {
		v := max * float64(i) / 3
		y := hf - cBottom - ph*float64(i)/3
		lbl := f1(v)
		if fmt != nil {
			lbl = fmt(v)
		}
		lc.YTicks = append(lc.YTicks, Axis{Label: lbl, Pos: y})
	}
	thin := thinLabels(xlabels)
	pw := wf - cLeft - cRight
	for i, l := range thin {
		if l == "" {
			continue
		}
		x := cLeft
		if len(xlabels) > 1 {
			x = cLeft + pw*float64(i)/float64(len(xlabels)-1)
		}
		lc.XTicks = append(lc.XTicks, Axis{Label: l, Pos: x})
	}
	return lc
}

// NewSparkline is a minimal line chart without ticks.
func NewSparkline(vals []float64, w, h int) LineChart {
	lc := NewLineChart(vals, nil, w, h, nil)
	lc.YTicks = nil
	lc.XTicks = nil
	return lc
}

// NewBarChart builds bar geometry for vals.
func NewBarChart(vals []float64, xlabels []string, w, h int, fmt func(float64) string) BarChart {
	wf, hf := clampWH(w, h)
	bc := BarChart{W: int(wf), H: int(hf)}
	if len(vals) == 0 {
		bc.Empty = true
		return bc
	}
	_, mx := scale(vals, wf, hf)
	bc.Max = mx
	allZero := true
	for _, v := range vals {
		if v > 0 {
			allZero = false
		}
	}
	if allZero {
		bc.Empty = true
	}
	pw := wf - cLeft - cRight
	n := len(vals)
	bw := pw / float64(n)
	for i, v := range vals {
		if v < 0 {
			v = 0
		}
		bh := int(math.Round((hf - cTop - cBottom) * (v / mx)))
		lbl := ""
		if i < len(xlabels) {
			lbl = xlabels[i]
		}
		bc.Bars = append(bc.Bars, BarRect{
			X: int(cLeft) + i*int(bw+0.5), Y: int(hf-cBottom) - bh,
			W: max(1, int(bw)-2), H: bh, Label: lbl, Value: v})
	}
	ph := hf - cTop - cBottom
	for i := 0; i <= 3; i++ {
		v := mx * float64(i) / 3
		lbl := f1(v)
		if fmt != nil {
			lbl = fmt(v)
		}
		bc.YTicks = append(bc.YTicks, Axis{Label: lbl, Pos: hf - cBottom - ph*float64(i)/3})
	}
	thin := thinLabels(xlabels)
	for i, l := range thin {
		if l == "" {
			continue
		}
		bc.XTicks = append(bc.XTicks, Axis{Label: l, Pos: cLeft + float64(i)*bw})
	}
	return bc
}

// StackedBars returns two layers sharing one scale.
func StackedBars(a, b []float64, xlabels []string, w, h int, fmt func(float64) string) (BarChart, BarChart) {
	n := max(len(a), len(b))
	sum := make([]float64, n)
	for i := 0; i < n; i++ {
		var v1, v2 float64
		if i < len(a) {
			v1 = a[i]
		}
		if i < len(b) {
			v2 = b[i]
		}
		sum[i] = v1 + v2
	}
	wf, hf := clampWH(w, h)
	var maxV float64
	for _, v := range sum {
		if v > maxV {
			maxV = v
		}
	}
	mx := niceMax(maxV)
	pw := wf - cLeft - cRight
	bw := pw / float64(max(1, n))
	mk := func(vals []float64, atop bool) BarChart {
		bc := BarChart{W: int(wf), H: int(hf), Max: mx}
		ph := hf - cTop - cBottom
		for i := 0; i < n; i++ {
			var v, under float64
			if i < len(vals) {
				v = vals[i]
			}
			if atop && i < len(a) {
				under = a[i]
			}
			bh := int(math.Round(ph * (v / mx)))
			lbl := ""
			if i < len(xlabels) {
				lbl = xlabels[i]
			}
			bc.Bars = append(bc.Bars, BarRect{X: int(cLeft) + i*int(bw+0.5),
				Y: int(hf-cBottom) - int(math.Round(ph*(under/mx))) - bh,
				W: max(1, int(bw)-2), H: bh, Label: lbl, Value: v})
		}
		return bc
	}
	return mk(a, false), mk(b, true)
}
