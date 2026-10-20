// SPDX-License-Identifier: 0BSD

package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sudo-Ivan/saves/internal/clicfg"
	"github.com/Sudo-Ivan/saves/internal/hub"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/internal/p2p"
	"github.com/Sudo-Ivan/saves/pkg/client"
)

// p2pIdent loads the device identity and peer set from the config dir.
func p2pIdent(cfgDir string) (*p2p.Identity, *p2p.PeerSet, error) {
	id, err := p2p.LoadIdentity(cfgDir)
	if err != nil {
		return nil, nil, err
	}
	ps, err := p2p.LoadPeers(cfgDir)
	return id, ps, err
}

// p2pTransport builds the pinned transport for a p2p:// URL.
func p2pTransport(cfgDir, deviceID string) (p2p.Transport, error) {
	id, ps, err := p2pIdent(cfgDir)
	if err != nil {
		return nil, err
	}
	peer, ok := ps.Get(deviceID)
	if !ok {
		return nil, fmt.Errorf("p2p: unknown peer %s", deviceID)
	}
	return p2p.NewTransport(id, ps, deviceID, peer.Addrs)
}

func init() {
	reg("p2p", "p2p <id|host|join|peers|unpair>", "peer to peer sync",
		func(ctx context.Context, e *Env, args []string) error {
			if len(args) == 0 {
				return usagef("p2p id|host|join|peers|unpair")
			}
			var c common
			cfg, paths, err := c.loadConfig(e)
			if err != nil {
				return err
			}
			sub := args[0]
			switch sub {
			case "id":
				id, _, err := p2pIdent(paths.Config)
				if err != nil {
					return err
				}
				fmt.Fprintln(e.Stdout, id.ID)
				return nil
			case "host":
				return p2pHost(ctx, e, args[1:], cfg, paths)
			case "join":
				return p2pJoin(ctx, e, args[1:], cfg, paths)
			case "peers":
				_, ps, err := p2pIdent(paths.Config)
				if err != nil {
					return err
				}
				for _, p := range ps.List() {
					fmt.Fprintf(e.Stdout, "%s %s %v\n", p.ID, p.Name, p.Addrs)
				}
				return nil
			case "unpair":
				if len(args) < 2 {
					return usagef("p2p unpair <id>")
				}
				_, ps, err := p2pIdent(paths.Config)
				if err != nil {
					return err
				}
				return ps.Remove(args[1])
			}
			return usagef("p2p %s", sub)
		})
}

// p2pHost runs the embedded hub + QUIC listener.
func p2pHost(ctx context.Context, e *Env, args []string, cfg *clicfg.Config, paths clicfg.Paths) error {
	dir := cfg.P2P.HostDir
	listen := cfg.P2P.Listen
	pair := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "start":
		case "--listen":
			i++
			listen = args[i]
		case "--dir":
			i++
			dir = args[i]
		case "--pair":
			pair = true
		}
	}
	if dir == "" {
		dir = filepath.Join(paths.State, "hub")
	}
	if listen == "" {
		listen = ":7414"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	hb, err := hub.Start(ctx, hub.Options{Dir: dir, Name: cfg.P2P.Name})
	if err != nil {
		return err
	}
	defer hb.Close()
	id, ps, err := p2pIdent(paths.Config)
	if err != nil {
		return err
	}
	pc, err := netx.ListenUDP(ctx, listen, 8<<20)
	if err != nil {
		return err
	}
	ln, err := p2p.Listen(pc, id, ps, hb.Handler())
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Fprintf(e.Stdout, "host id %s addr %s\n", id.ID, ln.Addr())
	if pair {
		mint := func(name string) (string, error) {
			return hb.MintToken(ctx, name, []string{"read", "write"})
		}
		pairListen := "127.0.0.1:0"
		if h, port, err := net.SplitHostPort(listen); err == nil {
			pairListen = net.JoinHostPort(h, "0")
			if n, err := strconv.Atoi(port); err == nil && n != 0 && n < 65535 {
				pairListen = net.JoinHostPort(h, strconv.Itoa(n+1))
			}
		}
		pc2, err := netx.ListenUDP(ctx, pairListen, 8<<20)
		if err != nil {
			return err
		}
		defer pc2.Close()
		code, wait, err := p2p.HostPair(ctx, pc2, id, ps, mint,
			p2p.PairOptions{Name: cfg.P2P.Name, ServiceAddrs: []string{ln.Addr().String()}})
		if err != nil {
			return err
		}
		fmt.Fprintf(e.Stdout, "pairing code %s on %s (10 min, single use)\n", code, pc2.LocalAddr())
		go func() {
			p, err := wait()
			if err == nil {
				fmt.Fprintf(e.Stdout, "paired %s %s\n", p.ID, p.Name)
			}
		}()
	}
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-ctx.Done():
	}
	return nil
}

// p2pJoin pairs with a host and writes server config.
func p2pJoin(ctx context.Context, e *Env, args []string, cfg *clicfg.Config, paths clicfg.Paths) error {
	if len(args) < 1 {
		return usagef("p2p join <code>@<host:port>")
	}
	at := strings.LastIndex(args[0], "@")
	if at < 0 {
		return usagef("p2p join <code>@<host:port>")
	}
	code, addr := args[0][:at], args[0][at+1:]
	id, ps, err := p2pIdent(paths.Config)
	if err != nil {
		return err
	}
	res, err := p2p.JoinPair(ctx, id, ps, addr, code, cfg.P2P.Name)
	if err != nil {
		return err
	}
	cfg.Server = "p2p://" + res.HostID
	cfg.Token = res.Token
	if err := cfg.Save(paths); err != nil {
		return err
	}
	fmt.Fprintf(e.Stdout, "paired %s %s\n", res.HostID, res.HostName)
	return nil
}

var _ = client.New
var _ = net.UDPAddr{}
