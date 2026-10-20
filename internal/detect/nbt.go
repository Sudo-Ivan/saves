// SPDX-License-Identifier: 0BSD

package detect

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// LevelInfo is the subset of level.dat used for display.
type LevelInfo struct {
	Name       string
	LastPlayed time.Time
	Version    string
	GameType   int64
	Hardcore   bool
}

const nbtMax = 64 << 20

// ParseLevelDat reads a gzip or raw NBT level.dat.
func ParseLevelDat(b []byte) (*LevelInfo, error) {
	r := bytes.NewReader(b)
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		b, err = io.ReadAll(io.LimitReader(gz, nbtMax))
		if err != nil {
			return nil, err
		}
	}
	l := &LevelInfo{}
	if err := nbtWalk(b, 0, l); err != nil {
		return nil, err
	}
	return l, nil
}

// nbtWalk scans NBT bytes for wanted tags, bounded depth.
func nbtWalk(b []byte, depth int, l *LevelInfo) error {
	if depth > 64 {
		return errors.New("nbt: depth")
	}
	i := 0
	for i+3 <= len(b) {
		tag := b[i]
		i++
		if tag == 0 {
			return nil
		}
		nameLen := int(binary.BigEndian.Uint16(b[i:]))
		i += 2
		if i+nameLen > len(b) {
			return errors.New("nbt: name")
		}
		name := string(b[i : i+nameLen])
		i += nameLen
		v, n, err := nbtValue(b[i:], tag, depth, l)
		if err != nil {
			return err
		}
		i += n
		switch name {
		case "LevelName":
			l.Name = v.str
		case "LastPlayed":
			l.LastPlayed = time.UnixMilli(v.i64)
		case "Name":
			if l.Version == "" {
				l.Version = v.str
			}
		case "GameType":
			l.GameType = v.i64
		case "hardcore":
			l.Hardcore = v.i64 != 0
		}
	}
	return nil
}

type nval struct {
	str string
	i64 int64
}

// nbtValue consumes one tag payload, returning value and bytes read.
func nbtValue(b []byte, tag byte, depth int, l *LevelInfo) (nval, int, error) {
	var v nval
	switch tag {
	case 1: // byte
		if len(b) < 1 {
			return v, 0, io.ErrUnexpectedEOF
		}
		v.i64 = int64(int8(b[0])) // #nosec G115 -- NBT byte to int64
		return v, 1, nil
	case 2: // short
		if len(b) < 2 {
			return v, 0, io.ErrUnexpectedEOF
		}
		v.i64 = int64(int16(binary.BigEndian.Uint16(b))) // #nosec G115 -- NBT short
		return v, 2, nil
	case 3, 5: // int, float
		if len(b) < 4 {
			return v, 0, io.ErrUnexpectedEOF
		}
		v.i64 = int64(int32(binary.BigEndian.Uint32(b))) // #nosec G115 -- NBT int
		return v, 4, nil
	case 4, 6: // long, double
		if len(b) < 8 {
			return v, 0, io.ErrUnexpectedEOF
		}
		v.i64 = int64(binary.BigEndian.Uint64(b)) // #nosec G115 -- NBT long
		return v, 8, nil
	case 7: // byte array
		if len(b) < 4 {
			return v, 0, io.ErrUnexpectedEOF
		}
		n := int(int32(binary.BigEndian.Uint32(b))) // #nosec G115 -- bounded below
		if n < 0 || 4+n > len(b) {
			return v, 0, errors.New("nbt: bytearray")
		}
		return v, 4 + n, nil
	case 8: // string
		if len(b) < 2 {
			return v, 0, io.ErrUnexpectedEOF
		}
		n := int(binary.BigEndian.Uint16(b)) // #nosec G115 -- 16 bit
		if 2+n > len(b) {
			return v, 0, errors.New("nbt: string")
		}
		v.str = string(b[2 : 2+n])
		return v, 2 + n, nil
	case 9: // list
		if len(b) < 5 {
			return v, 0, io.ErrUnexpectedEOF
		}
		et := b[0]
		n := int(int32(binary.BigEndian.Uint32(b[1:]))) // #nosec G115 -- sign checked below
		if n < 0 {
			return v, 0, errors.New("nbt: list")
		}
		off := 5
		j := 0
		for j < n && j < 1<<22 {
			if off >= len(b) {
				return v, off, nil
			}
			_, used, err := nbtValue(b[off:], et, depth+1, l)
			if err != nil || used == 0 {
				return v, off, nil // truncated list tolerated
			}
			off += used
			j++
		}
		return v, off, nil
	case 10: // compound
		// re-walk nested compound: consume entries
		i := 0
		for i+3 <= len(b) {
			if b[i] == 0 {
				return v, i + 1, nil
			}
			tag2 := b[i]
			i++
			nl := int(binary.BigEndian.Uint16(b[i:]))
			i += 2
			if i+nl > len(b) {
				return v, i, nil
			}
			nm := string(b[i : i+nl])
			i += nl
			val, used, err := nbtValue(b[i:], tag2, depth+1, l)
			if err != nil {
				return v, i, nil
			}
			i += used
			switch nm {
			case "LevelName":
				l.Name = val.str
			case "LastPlayed":
				l.LastPlayed = time.UnixMilli(val.i64)
			case "Name":
				if l.Version == "" {
					l.Version = val.str
				}
			case "GameType":
				l.GameType = val.i64
			case "hardcore":
				l.Hardcore = val.i64 != 0
			}
		}
		return v, i, nil
	case 11: // int array
		return nbtArray(b, 4)
	case 12: // long array
		return nbtArray(b, 8)
	default:
		return v, 0, errors.New("nbt: tag")
	}
}

func nbtArray(b []byte, sz int) (nval, int, error) {
	var v nval
	if len(b) < 4 {
		return v, 0, io.ErrUnexpectedEOF
	}
	n := int(int32(binary.BigEndian.Uint32(b))) // #nosec G115 -- bounded below
	if n < 0 || 4+n*sz > len(b) {
		return v, 0, errors.New("nbt: array")
	}
	return v, 4 + n*sz, nil
}
