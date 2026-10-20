// SPDX-License-Identifier: 0BSD

// Package icons renders deterministic tray status icons at init.
package icons

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"sync"
)

// State names a tray state icon.
type State int

const (
	OK State = iota
	Syncing
	Paused
	Conflict
	Error
	Offline
)

var palette = map[State]color.RGBA{
	OK:       {0x2e, 0x8b, 0x57, 0xff}, // green
	Syncing:  {0x1e, 0x88, 0xe5, 0xff}, // blue
	Paused:   {0xf9, 0xa8, 0x25, 0xff}, // amber
	Conflict: {0x8e, 0x24, 0xaa, 0xff}, // purple
	Error:    {0xe5, 0x39, 0x35, 0xff}, // red
	Offline:  {0x75, 0x75, 0x75, 0xff}, // grey
}

var sizes = []int{16, 22, 32, 64}

var (
	once  sync.Once
	cache map[State]map[int][]byte
)

// PNG returns the icon for state at size as PNG bytes (deterministic).
func PNG(s State, size int) []byte {
	once.Do(build)
	if m, ok := cache[s]; ok {
		return m[size]
	}
	return nil
}

// render draws a rounded square with a simple glyph per state.
func render(s State, size int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	c := palette[s]
	draw.Draw(img, img.Bounds(), &image.Uniform{c}, image.Point{}, draw.Src)
	fg := color.RGBA{0xff, 0xff, 0xff, 0xff}
	cx, cy := size/2, size/2
	switch s {
	case OK: // check
		for i := 0; i < size/3; i++ {
			for dx := 0; dx < 2; dx++ {
				img.Set(cx-size/4+i/2+dx, cy+i/2, fg)
				img.Set(cx-size/4+i/2+dx, cy+i/2+dx, fg)
				img.Set(cx+size/4-i/2+dx, cy+size/4-i/2, fg)
			}
		}
	case Syncing: // circular arrow ring
		for i := 0; i < size; i++ {
			for j := 0; j < size; j++ {
				dx, dy := i-cx, j-cy
				r2 := dx*dx + dy*dy
				r := size / 3
				if r2 >= (r-1)*(r-1) && r2 <= r*r {
					img.Set(i, j, fg)
				}
			}
		}
	case Paused: // two bars
		for i := cx - size/6; i < cx-size/12; i++ {
			for j := cy - size/4; j < cy+size/4; j++ {
				img.Set(i, j, fg)
			}
		}
		for i := cx + size/12; i < cx+size/6; i++ {
			for j := cy - size/4; j < cy+size/4; j++ {
				img.Set(i, j, fg)
			}
		}
	case Conflict: // X
		for i := size / 4; i < size-size/4; i++ {
			for dx := 0; dx < 2; dx++ {
				img.Set(i+dx, i, fg)
				img.Set(size-i+dx, i, fg)
			}
		}
	case Error: // ! bar + dot
		for j := size / 4; j < size/2; j++ {
			img.Set(cx, j, fg)
			img.Set(cx+1, j, fg)
		}
		for j := 3 * size / 4; j < size-size/4; j++ {
			img.Set(cx, j, fg)
			img.Set(cx+1, j, fg)
		}
	case Offline: // horizontal bar
		for i := size / 4; i < size-size/4; i++ {
			img.Set(i, cy, fg)
			img.Set(i, cy+1, fg)
		}
	}
	return img
}

func build() {
	cache = map[State]map[int][]byte{}
	for s := OK; s <= Offline; s++ {
		cache[s] = map[int][]byte{}
		for _, sz := range sizes {
			var b bytes.Buffer
			_ = png.Encode(&b, render(s, sz))
			cache[s][sz] = b.Bytes()
		}
	}
}

// ICO returns the icon as PNG-in-ICO for Windows.
func ICO(s State, size int) []byte {
	pngB := PNG(s, size)
	var b bytes.Buffer
	b.Write([]byte{0, 0, 1, 0, 1, 0}) // reserved, type=1, count=1
	w, h := byte(size), byte(size)    // #nosec G115 -- value bounded by the format or by max_chunk_bytes
	if size >= 256 {
		w, h = 0, 0
	}
	b.Write([]byte{w, h, 0, 0, 1, 0, 32, 0})
	var hdr [4]byte
	hdr[0] = byte(len(pngB))       // #nosec G115 -- value bounded by the format or by max_chunk_bytes
	hdr[1] = byte(len(pngB) >> 8)  // #nosec G115 -- value bounded by the format or by max_chunk_bytes
	hdr[2] = byte(len(pngB) >> 16) // #nosec G115 -- value bounded by the format or by max_chunk_bytes
	hdr[3] = byte(len(pngB) >> 24) // #nosec G115 -- value bounded by the format or by max_chunk_bytes
	b.Write(hdr[:])
	b.Write([]byte{0x16, 0, 0, 0}) // offset 22
	b.Write(pngB)
	return b.Bytes()
}
