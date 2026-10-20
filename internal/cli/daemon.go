// SPDX-License-Identifier: 0BSD

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Sudo-Ivan/saves/internal/autostart"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/saves/internal/clicfg"
	"github.com/Sudo-Ivan/saves/internal/daemon"
	"github.com/Sudo-Ivan/saves/internal/daemon/ctl"
	"github.com/Sudo-Ivan/saves/internal/detect"
	"github.com/Sudo-Ivan/saves/internal/notify"
	"github.com/Sudo-Ivan/saves/internal/tray"
	"github.com/Sudo-Ivan/saves/pkg/client"
)

func init() {
	reg("daemon", "daemon <run|start|stop|status|logs|pause|resume|sync|conflicts|resolve|install|uninstall|autostart-status>",
		"manage the background sync daemon",
		func(ctx context.Context, e *Env, args []string) error { return cmdDaemon(ctx, e, args) })
}

// daemonEndpoint reads the endpoint file.
func daemonEndpoint(e *Env) (ctl.Endpoint, error) {
	var ep ctl.Endpoint
	b, err := os.ReadFile(filepath.Join(e.Paths.State, "runtime", "daemon.json"))
	if err != nil {
		return ep, err
	}
	_ = json.Unmarshal(b, &ep)
	return ep, nil
}

// daemonCall hits the loopback API.
func daemonCall(e *Env, method, path string) (*http.Response, error) {
	ep, err := daemonEndpoint(e)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(method, "http://"+ep.Addr+path, nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+ep.Token)
	return (&http.Client{Transport: &http.Transport{
		DialContext: func(c context.Context, n, a string) (net.Conn, error) {
			return net.Dial("tcp", ep.Addr)
		}}}).Do(req)
}

// daemonCallBody posts a JSON body.
func daemonCallBody(e *Env, method, path, body string) (*http.Response, error) {
	ep, err := daemonEndpoint(e)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(method, "http://"+ep.Addr+path,
		strings.NewReader(body))
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+ep.Token)
	return (&http.Client{Transport: &http.Transport{
		DialContext: func(c context.Context, n, a string) (net.Conn, error) {
			return net.Dial("tcp", ep.Addr)
		}}}).Do(req)
}

func cmdDaemon(ctx context.Context, e *Env, args []string) error {
	if len(args) < 1 {
		return usagef("daemon: subcommand required")
	}
	sub := args[0]
	fs := flag.NewFlagSet("daemon "+sub, flag.ContinueOnError)
	var c common
	c.add(fs)
	if err := parseArgs(fs, args[1:]); err != nil {
		return usagef("daemon: %v", err)
	}
	switch sub {
	case "run":
		return runDaemon(ctx, e)
	case "start":
		exe, _ := os.Executable()
		var c0 common
		_, paths, _ := c0.loadConfig(e)
		pid, err := startDetached(e, exe, paths.State)
		if err != nil {
			return err
		}
		fmt.Fprintf(e.Stdout, "daemon pid %d\n", pid)
		return nil
	case "stop":
		r, err := daemonCall(e, "POST", "/stop")
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		fmt.Fprintln(e.Stdout, "stopped")
		return nil
	case "status":
		r, err := daemonCall(e, "GET", "/status")
		if err != nil {
			return &ExitError{3, fmt.Errorf("daemon not running")}
		}
		defer r.Body.Close()
		_, _ = io.Copy(e.Stdout, r.Body)
		return nil
	case "logs":
		r, err := daemonCall(e, "GET", "/logs?n=200")
		if err != nil {
			return err
		}
		defer r.Body.Close()
		if c.json {
			_, _ = io.Copy(e.Stdout, r.Body)
			return nil
		}
		var ents []struct {
			Time  string `json:"time"`
			Level string `json:"level"`
			Game  string `json:"game"`
			Msg   string `json:"message"`
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &ents); err != nil {
			return err
		}
		for _, le := range ents {
			fmt.Fprintf(e.Stdout, "%s %s %s %s\n", le.Time, le.Level, le.Game, le.Msg)
		}
		return nil
	case "pause", "resume":
		r, err := daemonCall(e, "POST", "/"+sub)
		if err != nil {
			return err
		}
		_ = r.Body.Close()
		return nil
	case "sync":
		r, err := daemonCall(e, "POST", "/sync")
		if err != nil {
			return err
		}
		_ = r.Body.Close()
		return nil
	case "resolve":
		if len(fs.Args()) < 2 {
			return usagef("daemon resolve <game> keep-local|keep-remote|keep-newest")
		}
		r, err := daemonCallBody(e, "POST", "/conflicts/resolve",
			fmt.Sprintf(`{"game":%q,"choice":%q}`, fs.Arg(0), fs.Arg(1)))
		if err != nil {
			return err
		}
		_ = r.Body.Close()
		return nil
	case "install", "uninstall", "autostart-status":
		var c0 common
		_, paths, _ := c0.loadConfig(e)
		exe, _ := os.Executable()
		exe, _ = filepath.EvalSymlinks(exe)
		spec := autostart.Spec{Target: "daemon", Exe: exe,
			ConfigDir: paths.Config, StateDir: paths.State,
			CacheDir: paths.Cache}
		var err error
		switch sub {
		case "install":
			err = autostart.Install(spec)
		case "uninstall":
			err = autostart.Uninstall(spec)
		default:
			ok, _ := autostart.Status(spec)
			fmt.Fprintf(e.Stdout, "autostart daemon=%v\n", ok)
			ok2, _ := autostart.Status(autostart.Spec{Target: "tray", Exe: exe, ConfigDir: paths.Config})
			fmt.Fprintf(e.Stdout, "autostart tray=%v\n", ok2)
			return nil
		}
		if err == nil {
			fmt.Fprintln(e.Stdout, sub+" ok")
		}
		return err
	case "conflicts":
		r, err := daemonCall(e, "GET", "/conflicts")
		if err != nil {
			return err
		}
		defer r.Body.Close()
		_, _ = io.Copy(e.Stdout, r.Body)
		return nil
	default:
		return usagef("daemon: unknown %q", sub)
	}
}

// runDaemon starts the daemon in-process (foreground).
func runDaemon(ctx context.Context, e *Env) error {
	var c0 common
	cfg, paths, err := c0.loadConfig(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(paths.State, "runtime"), 0o700); err != nil {
		return err
	}
	releaseLock, lerr := daemonLock(filepath.Join(paths.State, "runtime", "daemon.lock"))
	if lerr != nil {
		return lerr
	}
	defer releaseLock()
	_ = cfg
	d := daemon.New(daemon.Config{
		QuietPeriod:  time.Duration(cfg.Daemon.QuietPeriod),
		PollInterval: time.Duration(cfg.Daemon.PollInterval),
		MaxParallel:  cfg.Daemon.MaxParallel,
		HardCap:      time.Duration(cfg.Daemon.HardCap)},
		&daemonSyncer{e: e, path: paths})
	d.SetReachable(true)
	for _, t := range cfg.Tracked {
		d.Register(t.App+"/"+t.Slot, t.Slot)
		src := sourceFor(t)
		for _, r := range src.Roots {
			fw := &daemon.FSWatch{}
			ch, werr := fw.Watch(ctx, r.Dir)
			if werr != nil {
				continue
			}
			app := t.App + "/" + t.Slot
			go func() {
				for range ch {
					d.NoteLocal(app)
				}
			}()
		}
	}
	ctlSrv := ctl.New(d)
	addr, err := ctlSrv.Start(filepath.Join(paths.State, "runtime"))
	if err != nil {
		return err
	}
	fmt.Fprintln(e.Stdout, "daemon listening on", addr)
	// SSE remote events + slow poll fallback.
	cl, err := e.clientFor(cfg)
	if err == nil {
		go func() {
			for ev := range cl.Events(ctx) {
				d.SetReachable(true)
				if ev.Type == "lag" {
					d.RemoteAll()
					continue
				}
				if ev.Type == "head" {
					var m struct{ App, Slot string }
					_ = json.Unmarshal(ev.Data, &m)
					for _, t := range cfg.Tracked {
						if t.App == m.App && t.Slot == m.Slot {
							d.Remote(t.App + "/" + t.Slot)
						}
					}
				}
			}
			d.SetReachable(false)
		}()
	}
	go func() {
		iv := time.Duration(cfg.Daemon.PollInterval)
		tk := time.NewTicker(iv)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				d.RemoteAll()
			}
		}
	}()
	go func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		d.Stop()
		ctlSrv.Stop()
	}()
	// Re-resolve tracked games on config change (10s mtime poll) and SIGHUP.
	rescan := make(chan struct{}, 1)
	go func() {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		var lastMod time.Time
		cfgp := filepath.Join(paths.Config, "config.json")
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				if st, err := os.Stat(cfgp); err == nil && st.ModTime().After(lastMod) {
					lastMod = st.ModTime()
					select {
					case rescan <- struct{}{}:
					default:
					}
				}
			case <-hup:
				select {
				case rescan <- struct{}{}:
				default:
				}
			}
		}
	}()
	go func() {
		for range rescan {
			var c2 common
			nc, _, err := c2.loadConfig(e)
			if err != nil {
				continue
			}
			want := map[string]clicfg.Tracked{}
			for _, t := range nc.Tracked {
				want[t.App+"/"+t.Slot] = t
			}
			_, have := d.Status()
			for _, t := range want {
				key := t.App + "/" + t.Slot
				if _, ok := have[key]; !ok {
					d.Register(key, t.Slot)
					for _, r := range sourceFor(t).Roots {
						fw := &daemon.FSWatch{}
						ch, _ := fw.Watch(ctx, r.Dir)
						if ch != nil {
							go func(k string, ch <-chan string) {
								for range ch {
									d.NoteLocal(k)
								}
							}(key, ch)
						}
					}
				}
			}
			for k := range have {
				if _, ok := want[k]; !ok {
					d.Unregister(k)
				}
			}
		}
	}()
	d.Run(ctx)
	return nil
}

// daemonSyncer satisfies daemon.Syncer using the CLI client path.
type daemonSyncer struct {
	e    *Env
	path clicfg.Paths
}

func (ds *daemonSyncer) Sync(ctx context.Context, game, policy string) (daemon.SyncResult, error) {
	var c0 common
	cfg, _, err := c0.loadConfig(ds.e)
	if err != nil {
		return daemon.SyncResult{}, err
	}
	var t *clicfg.Tracked
	for i := range cfg.Tracked {
		key := cfg.Tracked[i].App + "/" + cfg.Tracked[i].Slot
		if key == game || cfg.Tracked[i].App == game {
			t = &cfg.Tracked[i]
			break
		}
	}
	if t == nil {
		return daemon.SyncResult{}, fmt.Errorf("daemon: unknown game %q", game)
	}
	// Defer while a minecraft world is locked.
	for _, r := range sourceFor(*t).Roots {
		if detect.IsWorldLocked(r.Dir) {
			return daemon.SyncResult{}, daemon.ErrLocked
		}
	}
	cl, err := ds.e.clientFor(cfg)
	if err != nil {
		return daemon.SyncResult{}, err
	}
	var strat client.ConflictStrategy
	pol := policy
	if pol == "" {
		pol = t.OnConflict
	}
	switch pol {
	case "keep-local":
		strat = client.KeepLocal
	case "keep-remote":
		strat = client.KeepRemote
	case "keep-newest":
		strat = client.KeepNewest
	default:
		strat = client.Fail
	}
	sr2, err := cl.Sync(ctx, t.App, t.Slot, sourceFor(*t), stateStore(ds.path),
		client.SyncOptions{OnConflict: strat,
			BackupDir: filepath.Join(ds.path.State, "backups", t.App, t.Slot,
				time.Now().Format(time.RFC3339))})
	var res daemon.SyncResult
	if sr2 != nil {
		if sr2.Push != nil {
			res.BytesUp = sr2.Push.BytesUploaded
			res.Unchanged = sr2.Push.Unchanged
		}
		if sr2.Pull != nil {
			res.BytesDown = sr2.Pull.Bytes
		}
	}
	var ce *client.ConflictError
	if errors.As(err, &ce) {
		return res, daemon.ErrConflict
	}
	return res, err
}

// cmdTrayInstall handles savesctl tray install|uninstall.
func init() {
	reg("tray", "tray [--no-start-daemon] | tray install|uninstall",
		"system tray app",
		func(ctx context.Context, e *Env, args []string) error {
			if len(args) > 0 && (args[0] == "install" || args[0] == "uninstall") {
				var c0 common
				_, paths, _ := c0.loadConfig(e)
				exe, _ := os.Executable()
				exe, _ = filepath.EvalSymlinks(exe)
				spec := autostart.Spec{Target: "tray", Exe: exe, ConfigDir: paths.Config}
				if args[0] == "install" {
					return autostart.Install(spec)
				}
				return autostart.Uninstall(spec)
			}
			return runTray(ctx, e, args)
		})
}

// runTray starts the systray app.
func runTray(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("tray", flag.ContinueOnError)
	noStart := fs.Bool("no-start-daemon", false, "")
	_ = parseArgs(fs, args)
	if tray.Headless() {
		return &ExitError{1, tray.ErrHeadless}
	}
	var c0 common
	_, paths, _ := c0.loadConfig(e)
	_ = os.MkdirAll(filepath.Join(paths.State, "runtime"), 0o700)
	release, err := daemonLock(filepath.Join(paths.State, "runtime", "tray.lock"))
	if err != nil {
		return err
	}
	defer release()
	if !*noStart {
		if _, err := daemonCall(e, "GET", "/status"); err != nil {
			exe, _ := os.Executable()
			_, _ = startDetached(e, exe, paths.State)
		}
	}
	ui := tray.SysUI{}
	var c common
	cfg, _, _ := c.loadConfig(e)
	_ = cfg
	done := make(chan struct{})
	go func() {
		// poll /status every 2 s, rebuild menu on change.
		var last string
		var lastLogID int64
		lt := &tray.LogTailer{N: notify.NewDedup(notify.NopNotifier{}), Enabled: true}
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-tick.C:
				lr, lerr := daemonCall(e, "GET",
					fmt.Sprintf("/logs?since=%d", lastLogID))
				if lerr == nil {
					lb, _ := io.ReadAll(lr.Body)
					_ = lr.Body.Close()
					var ents []struct {
						ID    int64  `json:"id"`
						Level string `json:"level"`
						Game  string `json:"game"`
						Msg   string `json:"message"`
					}
					if json.Unmarshal(lb, &ents) == nil {
						for _, le := range ents {
							lt.Feed(le.Level, le.Game, le.Msg)
							if le.ID > lastLogID {
								lastLogID = le.ID
							}
						}
					}
				}
				r, err := daemonCall(e, "GET", "/status")
				if err != nil {
					continue
				}
				b, _ := io.ReadAll(r.Body)
				_ = r.Body.Close()
				if string(b) == last {
					continue
				}
				last = string(b)
				var st struct {
					Paused bool `json:"paused"`
					Reach  bool `json:"server_reachable"`
					Games  map[string]struct {
						ID, Slot, State, LastError string `json:"-"`
					} `json:"games"`
				}
				var raw map[string]any
				_ = json.Unmarshal(b, &raw)
				st.Reach, _ = raw["server_reachable"].(bool)
				st.Paused, _ = raw["paused"].(bool)
				var ts tray.Status
				ts.Running = true
				ts.Paused = st.Paused
				ts.ServerReachable = st.Reach
				ts.Games = map[string]tray.GameState{}
				if gm, ok := raw["games"].(map[string]any); ok {
					for k, v := range gm {
						g := v.(map[string]any)
						gs := tray.GameState{ID: k}
						gs.State, _ = g["state"].(string)
						gs.LastError, _ = g["last_error"].(string)
						if lc, _ := g["pending_conflict"].(bool); lc {
							ts.Conflicts = append(ts.Conflicts, k)
						}
						ts.Games[k] = gs
					}
				}
				items := tray.BuildMenu(ts)
				// click handlers
				tray.Apply(&ui, items, func(id string) {
					act, game, _ := tray.Click(id)
					switch act {
					case "sync":
						_, _ = daemonCallBody(e, "POST", "/sync",
							fmt.Sprintf(`{"game":%q}`, game))
					case "pause":
						_, _ = daemonCallBody(e, "POST", "/pause",
							fmt.Sprintf(`{"game":%q}`, game))
					case "resume":
						_, _ = daemonCallBody(e, "POST", "/resume",
							fmt.Sprintf(`{"game":%q}`, game))
					case "resolve":
						parts := strings.SplitN(game, ":", 2)
						if len(parts) == 2 {
							_, _ = daemonCallBody(e, "POST", "/conflicts/resolve",
								fmt.Sprintf(`{"game":%q,"choice":%q}`, parts[0], parts[1]))
						}
					case "quit":
						tray.Quit()
					case "stop":
						_, _ = daemonCall(e, "POST", "/stop")
					case "start":
						exe, _ := os.Executable()
						_, _ = startDetached(e, exe, paths.State)
					}
				})
			}
		}
	}()
	ui.Run(func() {}, func() { close(done) })
	return nil
}
