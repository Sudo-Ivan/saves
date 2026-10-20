// SPDX-License-Identifier: 0BSD

package nettest

import (
	"context"
	"syscall"
	"testing"

	"github.com/Sudo-Ivan/saves/internal/netx"
)

func TestUDPBuffer(t *testing.T) {
	pc, err := netx.ListenUDP(context.Background(), "127.0.0.1:0", 7<<20)
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	type sc interface {
		SyscallConn() (syscall.RawConn, error)
	}
	c, ok := pc.(sc)
	if !ok {
		t.Skip("no raw conn")
	}
	rc, _ := c.SyscallConn()
	var got int
	rc.Control(func(fd uintptr) {
		got, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	})
	if got < 208<<10 {
		t.Fatalf("rcvbuf %d", got)
	}
}
