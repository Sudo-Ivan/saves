// SPDX-License-Identifier: 0BSD

package p2p

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/netx"
)

func pairPair(t *testing.T, ttl time.Duration) (id *Identity, jd *Identity, ph, pj *PeerSet, addr, code string, wait func() (Peer, error), minted *int) {
	t.Helper()
	ctx := context.Background()
	hd, jd2 := t.TempDir(), t.TempDir()
	H, _ := LoadIdentity(hd)
	J, _ := LoadIdentity(jd2)
	ph, _ = LoadPeers(hd)
	pj, _ = LoadPeers(jd2)
	pc, err := netx.ListenUDP(ctx, "127.0.0.1:0", 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	minted = &n
	mint := func(name string) (string, error) {
		n++
		return "sv1_x", nil
	}
	code, wait, err = HostPair(ctx, pc, H, ph, mint,
		PairOptions{Name: "h", TTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	return H, J, ph, pj, pc.LocalAddr().String(), code, wait, minted
}

func TestPairWrongCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, J, ph, pj, addr, _, _, minted := pairPair(t, time.Minute)
	bad := "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA"[:26]
	bad = strings.ReplaceAll("ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZ", "-", "-")
	for i := 0; i < 3; i++ {
		_, err := JoinPair(ctx, J, pj, addr, bad, "j")
		if err == nil {
			t.Fatalf("attempt %d succeeded with wrong code", i)
		}
	}
	if *minted != 0 {
		t.Fatal("mint called on failure")
	}
	if ph.Has(J.ID) || pj.Len() > 0 {
		t.Fatal("peers stored on failure")
	}
	t.Logf("attempts used: joiner rejected 3x")
}

func (p *PeerSet) Len() int { return len(p.List()) }

func TestPairSingleUse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, J, _, pj, addr, code, wait, _ := pairPair(t, time.Minute)
	go func() {
		res, err := JoinPair(ctx, J, pj, addr, code, "j")
		if err != nil {
			t.Error(err)
		}
		if res.Token == "" {
			t.Error("no token")
		}
	}()
	p, err := wait()
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != J.ID {
		t.Fatal("wrong peer")
	}
	// second join with same code must fail (host listener done)
	_, err = JoinPair(ctx, J, pj, addr, code, "j2")
	if err == nil {
		t.Fatal("second join succeeded")
	}
}

func TestPairTTL(t *testing.T) {
	_, J, _, pj, addr, code, wait, _ := pairPair(t, 300*time.Millisecond)
	time.Sleep(600 * time.Millisecond)
	if _, err := wait(); err == nil {
		t.Fatal("wait did not end")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_, err := JoinPair(ctx, J, pj, addr, code, "j")
	if err == nil {
		t.Fatal("join after TTL succeeded")
	}
}

func TestPairOversize(t *testing.T) {
	// parse a frame >4KiB
	var b [4100]byte
	if err := readMsg(strings.NewReader(string(b[:])), &map[string]string{}); err == nil {
		t.Fatal("oversize accepted")
	}
}

func FuzzPairingMessages(f *testing.F) {
	f.Add([]byte{0, 0, 0, 4, 'a', 'b', 'c', 'd'})
	f.Fuzz(func(t *testing.T, data []byte) {
		var v map[string]string
		_ = readMsg(bytesReader(data), &v)
	})
}

func bytesReader(b []byte) *strings.Reader { return strings.NewReader(string(b)) }

func FuzzParsePairCode(f *testing.F) {
	f.Add("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GG")
	f.Fuzz(func(t *testing.T, s string) {
		_, err := parseCode(s)
		_ = err
	})
}

func TestParseCodeRoundTrip(t *testing.T) {
	c, b := makeCode()
	b2, err := parseCode(c)
	if err != nil || fmt.Sprintf("%x", b) != fmt.Sprintf("%x", b2) {
		t.Fatal("roundtrip")
	}
	if _, err := parseCode(strings.ToLower(c)); err != nil {
		t.Fatal("lower")
	}
	if _, err := parseCode(strings.ReplaceAll(c, "-", " ")); err != nil {
		t.Fatal("spaces")
	}
}
