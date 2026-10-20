// SPDX-License-Identifier: 0BSD

// Package config loads and validates the savesd JSON configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that decodes from human strings such as
// "30s", "5m", "24h", or "90d" and from bare numbers, which mean seconds.
type Duration time.Duration

// ParseDuration parses a duration string. Accepted units are ns, us, ms,
// s, m, h, and d (24 hours). A bare number means seconds.
func ParseDuration(s string) (Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("duration: empty")
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return Duration(n * float64(time.Second)), nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil {
			return 0, fmt.Errorf("duration %q: %w", s, err)
		}
		return Duration(n * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("duration %q: %w", s, err)
	}
	return Duration(d), nil
}

// Duration returns the value as time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String renders the duration in a compact human form.
func (d Duration) String() string {
	v := time.Duration(d)
	if v%24*time.Hour == 0 {
		return strconv.FormatInt(int64(v/(24*time.Hour)), 10) + "d"
	}
	return v.String()
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		v, err := ParseDuration(s)
		if err != nil {
			return err
		}
		*d = v
		return nil
	}
	n, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("duration: %w", err)
	}
	*d = Duration(n * float64(time.Second))
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(d.String())), nil
}

// Size is a byte count that decodes from human strings such as "512MiB",
// "10GB", or "1TiB" and from bare numbers, which mean bytes.
type Size int64

var sizeUnits = map[string]float64{
	"":  1,
	"b": 1,
	"k": 1e3, "kb": 1e3, "kib": 1 << 10,
	"m": 1e6, "mb": 1e6, "mib": 1 << 20,
	"g": 1e9, "gb": 1e9, "gib": 1 << 30,
	"t": 1e12, "tb": 1e12, "tib": 1 << 40,
	"p": 1e15, "pb": 1e15, "pib": 1 << 50,
}

// ParseSize parses a byte size string. Suffixes are case insensitive.
// Decimal units (KB, MB, GB, TB, PB) are powers of ten, binary units
// (KiB, MiB, GiB, TiB, PiB) are powers of two. A bare number means bytes.
func ParseSize(s string) (Size, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("size: empty")
	}
	i := 0
	for i < len(s) && (s[i] == '+' || s[i] == '-' || s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	num, unit := strings.TrimSpace(s[:i]), strings.ToLower(strings.TrimSpace(s[i:]))
	mult, ok := sizeUnits[unit]
	if !ok {
		return 0, fmt.Errorf("size %q: unknown unit %q", s, unit)
	}
	n, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", s, err)
	}
	v := n * mult
	if v > math.MaxInt64 || v < math.MinInt64 {
		return 0, fmt.Errorf("size %q: out of range", s)
	}
	return Size(v), nil
}

// Int64 returns the byte count.
func (s Size) Int64() int64 { return int64(s) }

// String renders the size using the largest exact binary unit.
func (s Size) String() string {
	v := int64(s)
	for _, u := range []struct {
		name string
		mult int64
	}{{"PiB", 1 << 50}, {"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if v%u.mult == 0 && v/u.mult != 0 {
			return strconv.FormatInt(v/u.mult, 10) + u.name
		}
	}
	return strconv.FormatInt(v, 10)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Size) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil
	}
	if b[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		v, err := ParseSize(str)
		if err != nil {
			return err
		}
		*s = v
		return nil
	}
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("size: %w", err)
	}
	*s = Size(n)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (s Size) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(s.String())), nil
}
