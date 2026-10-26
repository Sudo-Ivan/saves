// SPDX-License-Identifier: 0BSD

package server

import (
	"regexp"
	"testing"
)

var nanRe = regexp.MustCompile(`NaN|Inf`)

func TestNiceMax(t *testing.T) {
	for _, tc := range []struct{ in, want float64 }{
		{0, 1}, {1, 1}, {1.5, 2}, {2.2, 2.5}, {3, 5}, {9, 10},
		{11, 20}, {99, 100}, {1e15, 1e15},
	} {
		if got := niceMax(tc.in); got != tc.want {
			t.Fatalf("niceMax(%v)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestLineChart(t *testing.T) {
	lc := NewLineChart([]float64{1, 3, 2, 5}, []string{"a", "b", "c", "d"}, 300, 120, nil)
	if lc.Empty || len(lc.Points) == 0 || len(lc.Area) == 0 {
		t.Fatal("empty output")
	}
	if len(lc.YTicks) != 4 {
		t.Fatalf("yticks=%d", len(lc.YTicks))
	}
	if nanRe.MatchString(lc.Points) || nanRe.MatchString(lc.Area) {
		t.Fatal("NaN/Inf in output")
	}
	// thinning: 30 labels -> at most 6 non-empty ticks
	xl := make([]string, 30)
	for i := range xl {
		xl[i] = "d"
	}
	lc2 := NewLineChart(make([]float64, 30), xl, 300, 120, nil)
	n := 0
	for _, a := range lc2.XTicks {
		if a.Label != "" {
			n++
		}
	}
	if n > 6 {
		t.Fatalf("thinned=%d", n)
	}
	// empty and all-zero
	for _, in := range [][]float64{{}, {0, 0, 0}} {
		l := NewLineChart(in, nil, 300, 120, nil)
		if !l.Empty || nanRe.MatchString(l.Points+l.Area) {
			t.Fatalf("in=%v", in)
		}
	}
	// single point renders segment
	l3 := NewLineChart([]float64{5}, nil, 300, 120, nil)
	if len(l3.Points) == 0 {
		t.Fatal("single point empty")
	}
	// huge values finite
	l4 := NewLineChart([]float64{1e15, 1e14}, nil, 300, 120, nil)
	if nanRe.MatchString(l4.Points + l4.Area) {
		t.Fatal("huge value broke")
	}
	// negative clamped
	l5 := NewLineChart([]float64{-5, 3}, nil, 300, 120, nil)
	if nanRe.MatchString(l5.Points) {
		t.Fatal("negative broke")
	}
	// deterministic
	a := NewLineChart([]float64{1, 2}, nil, 200, 80, nil)
	b := NewLineChart([]float64{1, 2}, nil, 200, 80, nil)
	if a.Points != b.Points || a.Area != b.Area {
		t.Fatal("nondeterministic")
	}
	// min size
	l6 := NewLineChart([]float64{1}, nil, 10, 10, nil)
	if l6.W < 120 || l6.H < 40 {
		t.Fatal("no clamp")
	}
}

func TestBarChart(t *testing.T) {
	bc := NewBarChart([]float64{2, 4, 1}, []string{"a", "b", "c"}, 300, 120, nil)
	if len(bc.Bars) != 3 || bc.Empty {
		t.Fatal("bars")
	}
	for _, b := range bc.Bars {
		if float64(b.X) < cLeft-1 || float64(b.Y) < cTop-1 || float64(b.Y+b.H) > 120 {
			t.Fatalf("bar outside plot: %+v", b)
		}
		if nanRe.MatchString(b.Label) {
			t.Fatal("nan label")
		}
	}
	empty := NewBarChart(nil, nil, 300, 120, nil)
	if !empty.Empty {
		t.Fatal("not empty")
	}
}

func TestStackedAndSpark(t *testing.T) {
	a, b := StackedBars([]float64{1, 2}, []float64{1, 1}, []string{"x", "y"}, 300, 120, nil)
	if a.Max != b.Max {
		t.Fatal("scales differ")
	}
	if len(a.Bars) != 2 || len(b.Bars) != 2 {
		t.Fatal("layer bars")
	}
	// second layer sits on top of the first
	if b.Bars[0].Y+b.Bars[0].H != a.Bars[0].Y {
		t.Fatalf("stack: a=%d b=%d", a.Bars[0].Y, b.Bars[0].Y+b.Bars[0].H)
	}
	sp := NewSparkline([]float64{1, 2, 3}, 100, 30)
	if len(sp.YTicks) != 0 || len(sp.XTicks) != 0 || len(sp.Points) == 0 {
		t.Fatal("sparkline")
	}
}
