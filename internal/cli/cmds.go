// SPDX-License-Identifier: 0BSD

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/clicfg"
	"github.com/Sudo-Ivan/saves/internal/detect"
	"github.com/Sudo-Ivan/saves/pkg/client"
)

func init() {
	reg("setup", "setup [--server URL --token T] [--device-name N]", "configure savesctl", cmdSetup)
	reg("games", "games list|detect [--all] [--store S]", "list detected games", cmdGames)
	reg("track", "track add|list|rm|auto|enable|disable", "manage tracked games", cmdTrack)
	reg("status", "status [game...]", "show sync status", cmdStatus)
	reg("push", "push [game...] [--label L] [--force]", "push saves", cmdSyncOp("push"))
	reg("pull", "pull [game...] [--snapshot ID]", "pull saves", cmdSyncOp("pull"))
	reg("sync", "sync [game...]", "sync saves", cmdSyncOp("sync"))
	reg("snapshots", "snapshots <game>", "list snapshots", cmdSnapshots)
	reg("restore", "restore <game> [--snapshot ID] [--to DIR]", "restore a snapshot", cmdRestore)
	reg("delete-snapshot", "delete-snapshot <game> <id>", "delete a snapshot", cmdDeleteSnapshot)
	reg("delete-slot", "delete-slot <app> <slot>", "delete a slot", cmdDeleteSlot)
	reg("backups", "backups list|restore|prune", "safety backups", cmdBackups)
	reg("doctor", "doctor", "check setup", cmdDoctor)
	reg("completion", "completion bash|zsh|fish|powershell", "shell completion", cmdCompletion)
	reg("help", "help <cmd>", "show help", func(ctx context.Context, e *Env, a []string) error {
		if len(a) == 0 {
			fmt.Fprint(e.Stdout, helpText())
			return nil
		}
		if c, ok := registry[a[0]]; ok {
			fmt.Fprintf(e.Stdout, "savesctl %s\n\n%s\n", c.Usage, c.Help)
			return nil
		}
		return usagef("no such command %q", a[0])
	})
}

func cmdSetup(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	var c common
	c.add(fs)
	name := fs.String("device-name", "", "device name")
	register := fs.Bool("register", false, "register")
	trackAll := fs.Bool("track-all", false, "track detected games")
	if err := parseArgs(fs, args); err != nil {
		return usagef("setup: %v", err)
	}
	cfg, paths, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	if cfg.Server == "" {
		v, ok := prompt(e, "server URL")
		if !ok {
			return &ExitError{ExUsage, fmt.Errorf("--server required")}
		}
		cfg.Server = v
	}
	if cfg.Token == "" {
		v, _ := prompt(e, "token (empty to register)")
		if v != "" {
			cfg.Token = v
		}
	}
	if cfg.DeviceName == "" {
		if v, _ := prompt(e, "device name"); v != "" {
			cfg.DeviceName = v
		}
	}
	if *name != "" {
		cfg.DeviceName = *name
	}
	if *register || cfg.Token == "" {
		cl, err := e.clientFor(cfg)
		if err != nil {
			return err
		}
		_, tok, err := cl.Register(ctx, "")
		if err != nil {
			return err
		}
		cfg.Token = tok
	}
	if cfg.Token == "" {
		return &ExitError{ExUsage, fmt.Errorf("--token or configured token required")}
	}
	if err := cfg.Save(paths); err != nil {
		return err
	}
	if *trackAll {
		return cmdTrackAuto(ctx, e, cfg, paths)
	}
	fmt.Fprintln(e.Stdout, "configured")
	return nil
}

// detectNow runs detection over the real home.
func detectNow(ctx context.Context, e *Env) ([]detect.Game, error) {
	env := detect.DefaultEnv()
	return detect.DefaultDetector().Detect(ctx, env, detect.FS(os.DirFS("/")))
}

func cmdGames(ctx context.Context, e *Env, args []string) error {
	sub := "list"
	rest := args
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		sub = rest[0]
		rest = rest[1:]
	}
	fs := flag.NewFlagSet("games", flag.ContinueOnError)
	var c common
	c.add(fs)
	store := fs.String("store", "", "filter store")
	known := fs.Bool("known-only", false, "only games with save locations")
	_ = fs.Bool("locked", false, "")
	_ = fs.Bool("include-config", false, "")
	if err := parseArgs(fs, rest); err != nil {
		return usagef("games: %v", err)
	}
	_ = fs.Args()
	switch sub {
	case "update":
		cfg, paths, err := c.loadConfig(e)
		if err != nil {
			return err
		}
		url := cfg.ManifestURL
		if fs.NArg() > 1 {
			url = fs.Arg(1)
		}
		mf, err := detect.DownloadManifest(ctx, url, paths.Cache)
		if err != nil {
			return err
		}
		f, err := os.Open(mf) // #nosec G304 -- manifest under our cache dir
		if err != nil {
			return err
		}
		defer f.Close()
		ix, err := detect.ParseManifest(f)
		if err != nil {
			return err
		}
		if err := ix.Save(filepath.Join(paths.Cache, "index.json")); err != nil {
			return err
		}
		if c.json {
			return json.NewEncoder(e.Stdout).Encode(map[string]any{"games": len(ix.Games), "path": mf})
		}
		fmt.Fprintf(e.Stdout, "%d games indexed (up to date)\n", len(ix.Games))
		return nil
	case "list", "detect":
		games, err := detectNow(ctx, e)
		if err != nil {
			return err
		}
		if ix, err := detect.LoadIndex(e.Paths.Cache + "/index.json"); err == nil {
			env := detect.DefaultEnv()
			for i := range games {
				if en, ok := ix.Lookup(games[i]); ok {
					games[i].Locations = ix.ApplyManifest(games[i], en, env, os.DirFS("/"))
					games[i].Known = len(games[i].Locations) > 0
				}
			}
		} else if !c.json {
			fmt.Fprintln(e.Stderr, "hint: run savesctl games update for save locations")
		}
		type row struct {
			ID, Title, Store, Slot string
			Known                  bool
		}
		var rows []row
		for _, g := range games {
			if *store != "" && g.Store != *store {
				continue
			}
			if *known && !g.Known {
				continue
			}
			rows = append(rows, row{g.ID, g.Title, g.Store, g.Slot, g.Known})
		}
		if c.json {
			return json.NewEncoder(e.Stdout).Encode(rows)
		}
		for _, r := range rows {
			fmt.Fprintf(e.Stdout, "%-32s %-10s %-16s %s\n", r.ID, r.Store, r.Slot, r.Title)
		}
		return nil
	}
	return usagef("games: unknown subcommand %q", sub)
}

func cmdTrack(ctx context.Context, e *Env, args []string) error {
	sub := "list"
	rest := args
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		sub = rest[0]
		rest = rest[1:]
	}
	fs := flag.NewFlagSet("track", flag.ContinueOnError)
	var c common
	c.add(fs)
	path := fs.String("path", "", "manual save dir")
	app := fs.String("app", "", "manual app id")
	slot := fs.String("slot", "default", "slot")
	key := fs.String("key", "save", "root key")
	if err := parseArgs(fs, rest); err != nil {
		return usagef("track: %v", err)
	}
	rest = fs.Args()
	cfg, paths, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	switch sub {
	case "add":
		if *path != "" {
			if *app == "" {
				return usagef("--app required with --path")
			}
			cfg.Tracked = append(cfg.Tracked, clicfg.Tracked{
				App: *app, Slot: *slot, Title: *app, Mode: "manual",
				Roots: map[string]string{*key: *path}, Enabled: true})
			if err := cfg.Save(paths); err != nil {
				return err
			}
			fmt.Fprintf(e.Stdout, "tracked %s/%s\n", *app, *slot)
			return nil
		}
		if len(rest) == 0 {
			return usagef("track add <game-id> or --path")
		}
		appID, sl, err := clicfg.GameRef(rest[0])
		if err != nil {
			return usagef("track add: %v", err)
		}
		games, err := detectNow(ctx, e)
		if err != nil {
			return err
		}
		if ix, err := detect.LoadIndex(e.Paths.Cache + "/index.json"); err == nil {
			env := detect.DefaultEnv()
			for i := range games {
				if en, ok := ix.Lookup(games[i]); ok {
					games[i].Locations = ix.ApplyManifest(games[i], en, env, os.DirFS("/"))
					games[i].Known = len(games[i].Locations) > 0
				}
			}
		} else if !c.json {
			fmt.Fprintln(e.Stderr, "hint: run savesctl games update for save locations")
		}
		for _, g := range games {
			if g.ID == appID && (g.Slot == sl || g.Slot == "") {
				roots := map[string]string{}
				for _, l := range g.Locations {
					if l.Exists && l.Unsupported == "" {
						roots[l.Key] = l.Dir
					}
				}
				cfg.Tracked = append(cfg.Tracked, clicfg.Tracked{
					App: g.ID, Slot: func() string {
						if g.Slot != "" {
							return g.Slot
						}
						return sl
					}(),
					Title: g.Title, Mode: "auto", Roots: roots, Enabled: true})
				if err := cfg.Save(paths); err != nil {
					return err
				}
				fmt.Fprintf(e.Stdout, "tracked %s\n", g.ID)
				return nil
			}
		}
		var sugg []string
		for _, g := range games {
			if strings.Contains(g.ID, appID) || strings.Contains(strings.ToLower(g.Title), strings.ToLower(appID)) {
				sugg = append(sugg, g.ID+"/"+g.Slot)
			}
		}
		msg := fmt.Sprintf("game %q not detected", appID)
		if len(sugg) > 0 {
			msg += "; did you mean: " + strings.Join(sugg, ", ")
		}
		return &ExitError{ExError, fmt.Errorf("%s", msg)}
	case "list":
		for _, t := range cfg.Tracked {
			en := "enabled"
			if !t.Enabled {
				en = "disabled"
			}
			fmt.Fprintf(e.Stdout, "%s/%s %s %s\n", t.App, t.Slot, t.Mode, en)
		}
		return nil
	case "rm":
		if len(rest) == 0 {
			return usagef("track rm <game-id>")
		}
		appID, sl, _ := clicfg.GameRef(rest[0])
		var keep []clicfg.Tracked
		for _, t := range cfg.Tracked {
			if !(t.App == appID && t.Slot == sl) {
				keep = append(keep, t)
			}
		}
		cfg.Tracked = keep
		return cfg.Save(paths)
	case "auto":
		return cmdTrackAuto(ctx, e, cfg, paths)
	case "enable", "disable":
		if len(rest) == 0 {
			return usagef("track %s <game-id>", sub)
		}
		appID, sl, _ := clicfg.GameRef(rest[0])
		for i := range cfg.Tracked {
			if cfg.Tracked[i].App == appID && cfg.Tracked[i].Slot == sl {
				cfg.Tracked[i].Enabled = sub == "enable"
			}
		}
		return cfg.Save(paths)
	}
	return usagef("track: unknown subcommand %q", sub)
}

func cmdTrackAuto(ctx context.Context, e *Env, cfg *clicfg.Config, paths clicfg.Paths) error {
	games, err := detectNow(ctx, e)
	if err != nil {
		return err
	}
	n := 0
	have := map[string]bool{}
	for _, t := range cfg.Tracked {
		have[t.App+"/"+t.Slot] = true
	}
	for _, g := range games {
		slot := g.Slot
		if slot == "" {
			slot = "default"
		}
		if have[g.ID+"/"+slot] {
			continue
		}
		if !g.Known && g.Store != "minecraft" {
			continue
		}
		roots := map[string]string{}
		for _, l := range g.Locations {
			if l.Exists && l.Unsupported == "" {
				roots[l.Key] = l.Dir
			}
		}
		if len(roots) == 0 {
			continue
		}
		cfg.Tracked = append(cfg.Tracked, clicfg.Tracked{
			App: g.ID, Slot: slot, Title: g.Title, Mode: "auto",
			Roots: roots, Enabled: true})
		n++
	}
	if err := cfg.Save(paths); err != nil {
		return err
	}
	fmt.Fprintf(e.Stdout, "tracked %d games\n", n)
	return nil
}

// prompt reads a line from stdin; non-TTY scripted input works.
func prompt(e *Env, label string) (string, bool) {
	fmt.Fprintf(e.Stdout, "%s: ", label)
	var line string
	buf := make([]byte, 0, 64)
	one := make([]byte, 1)
	for {
		n, err := e.Stdin.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				break
			}
			buf = append(buf, one[0])
		}
		if err != nil {
			break
		}
	}
	line = strings.TrimSpace(string(buf))
	return line, line != ""
}

// sourceFor builds a client.Source for a tracked entry.
func sourceFor(t clicfg.Tracked) client.Source {
	var roots []client.Root
	for k, d := range t.Roots {
		roots = append(roots, client.Root{Key: k, Dir: d})
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Key < roots[j].Key })
	return client.Source{Roots: roots}
}

func stateStore(paths clicfg.Paths) client.StateStore {
	return &client.FileStore{Dir: filepath.Join(paths.State, "sync")}
}

func cmdStatus(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var c common
	c.add(fs)
	if err := parseArgs(fs, args); err != nil {
		return usagef("status: %v", err)
	}
	cfg, paths, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	cl, err := e.clientFor(cfg)
	if err != nil {
		return err
	}
	st := stateStore(paths)
	for _, t := range cfg.Tracked {
		if !t.Enabled {
			continue
		}
		pl, err := cl.Plan(ctx, t.App, t.Slot, sourceFor(t), st)
		if err != nil {
			fmt.Fprintf(e.Stdout, "%s/%s error: %v\n", t.App, t.Slot, err)
			continue
		}
		fmt.Fprintf(e.Stdout, "%s/%s %s\n", t.App, t.Slot, pl.State)
	}
	return nil
}

func cmdSyncOp(op string) func(context.Context, *Env, []string) error {
	return func(ctx context.Context, e *Env, args []string) error {
		fs := flag.NewFlagSet(op, flag.ContinueOnError)
		var c common
		c.add(fs)
		label := fs.String("label", "", "push label")
		force := fs.Bool("force", false, "force")
		dry := fs.Bool("dry-run", false, "dry run")
		all := fs.Bool("all", false, "all tracked")
		oc := fs.String("on-conflict", "", "conflict strategy: ask|keep-local|keep-remote|keep-newest|fail")
		forceLocked := fs.Bool("force-locked", false, "push locked worlds anyway")
		if err := parseArgs(fs, args); err != nil {
			return usagef(op+": %v", err)
		}
		cfg, paths, err := c.loadConfig(e)
		if err != nil {
			return err
		}
		cl, err := e.clientFor(cfg)
		if err != nil {
			return err
		}
		st := stateStore(paths)
		want := map[string]bool{}
		for _, a := range fs.Args() {
			if !strings.Contains(a, "/") {
				want[a+"/*"] = true
				continue
			}
			appID, sl, _ := clicfg.GameRef(a)
			want[appID+"/"+sl] = true
		}
		matched := len(want) == 0 || *all
		var retErr error
		for _, t := range cfg.Tracked {
			if !t.Enabled {
				continue
			}
			if !*all && len(want) > 0 && !want[t.App+"/"+t.Slot] && !want[t.App+"/*"] {
				continue
			}
			matched = true
			src := sourceFor(t)
			if (op == "push" || op == "sync") && !*forceLocked && strings.HasPrefix(t.App, "minecraft") {
				blocked := false
				for _, d := range t.Roots {
					if detect.IsWorldLocked(d) {
						fmt.Fprintf(e.Stderr, "%s/%s: world is locked (running?); use --force-locked\n", t.App, t.Slot)
						blocked = true
					}
				}
				if blocked {
					return &ExitError{ExError, fmt.Errorf("%s/%s: world is locked; use --force-locked", t.App, t.Slot)}
				}
			}
			var err error
			var pr *client.PushResult
			var plr *client.PullResult
			switch op {
			case "push":
				pr, err = cl.Push(ctx, t.App, t.Slot, src, st,
					client.PushOptions{Label: *label, Force: *force, DryRun: *dry})
			case "pull":
				plr, err = cl.Pull(ctx, t.App, t.Slot, "", src, st,
					client.PullOptions{DryRun: *dry, Delete: true,
						BackupDir: filepath.Join(paths.State, "backups", t.App, t.Slot,
							e.Now().Format(time.RFC3339))})
			case "sync":
				var strat client.ConflictStrategy
				pol := t.OnConflict
				if *oc != "" {
					pol = *oc
				}
				switch pol {
				case "keep-local":
					strat = client.KeepLocal
				case "keep-remote":
					strat = client.KeepRemote
				case "keep-newest":
					strat = client.KeepRemote
				case "ask":
					pl, perr := cl.Plan(ctx, t.App, t.Slot, src, st)
					if perr == nil && pl.State == client.Conflict {
						fmt.Fprintf(e.Stdout, "%s/%s: %d local changes vs %d remote\n", t.App, t.Slot, len(pl.AddedLocal)+len(pl.ChangedLocal), pl.LocalBytes)
						v, ok := prompt(e, "conflict: keep-local/keep-remote/keep-newest/skip")
						if !ok {
							err = &ExitError{ExConflict, fmt.Errorf("conflict unresolved")}
							if retErr == nil {
								retErr = err
							}
							fmt.Fprintf(e.Stderr, "%s/%s: conflict unresolved\n", t.App, t.Slot)
							continue
						}
						switch v {
						case "keep-local":
							strat = client.KeepLocal
						case "keep-remote", "keep-newest":
							strat = client.KeepRemote
						default:
							continue
						}
					} else {
						strat = client.Fail
					}
				default:
					strat = client.Fail
				}
				var sr *client.SyncResult
				sr, err = cl.Sync(ctx, t.App, t.Slot, src, st, client.SyncOptions{OnConflict: strat, BackupDir: filepath.Join(paths.State, "backups", t.App, t.Slot, e.Now().Format(time.RFC3339))})
				if sr != nil {
					pr, plr = sr.Push, sr.Pull
				}
			}
			if err != nil {
				fmt.Fprintf(e.Stderr, "%s/%s: %v\n", t.App, t.Slot, err)
				if retErr == nil {
					retErr = err
				}
				continue
			}
			if c.json {
				out := map[string]any{"app": t.App, "slot": t.Slot, "op": op}
				if pr != nil {
					out["files"] = pr.Files
					out["bytes"] = pr.Bytes
					out["chunks"] = pr.Chunks
					out["uploaded_chunks"] = pr.Uploaded
					out["deduped_chunks"] = pr.Deduped
					out["uploaded_bytes"] = pr.BytesUploaded
					out["unchanged"] = pr.Unchanged
					out["skipped"] = pr.Skipped
					out["skipped_files"] = pr.SkippedFiles
					// stderr: one line per skipped file, summarized >10.
					if len(pr.SkippedFiles) > 0 && !c.json {
						n := len(pr.SkippedFiles)
						limit := n
						if n > 10 {
							limit = 10
						}
						for i := 0; i < limit; i++ {
							fmt.Fprintf(e.Stderr, "skipped %s: %s\n",
								pr.SkippedFiles[i].Path, pr.SkippedFiles[i].Reason)
						}
						if n > 10 {
							fmt.Fprintf(e.Stderr, "skipped %d files total\n", n)
						}
					}
					out["duration_ms"] = pr.Duration.Milliseconds()
				}
				if plr != nil {
					out["files"] = plr.Written
					out["bytes"] = plr.Bytes
					out["downloaded_bytes"] = plr.Downloaded
					out["downloaded_chunks"] = plr.Chunks
					out["deleted"] = plr.Deleted
					out["duration_ms"] = plr.Duration.Milliseconds()
				}
				_ = json.NewEncoder(e.Stdout).Encode(out)
				continue
			}
			fmt.Fprintf(e.Stdout, "%s/%s %s ok\n", t.App, t.Slot, op)
		}
		if !matched {
			return usagef("%s: no tracked game matches %v", op, fs.Args())
		}
		return retErr
	}
}

func cmdSnapshots(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("snapshots", flag.ContinueOnError)
	var c common
	c.add(fs)
	if err := parseArgs(fs, args); err != nil {
		return usagef("snapshots: %v", err)
	}
	if fs.NArg() < 1 {
		return usagef("snapshots <game>")
	}
	cfg, _, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	cl, err := e.clientFor(cfg)
	if err != nil {
		return err
	}
	appID, slot, _ := clicfg.GameRef(fs.Arg(0))
	for s := range mustIter(cl.ListSnapshots(ctx, appID, slot)) {
		fmt.Fprintf(e.Stdout, "%s %s\n", s.ID, s.Label)
	}
	return nil
}

func cmdRestore(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	var c common
	c.add(fs)
	snap := fs.String("snapshot", "", "snapshot id")
	to := fs.String("to", "", "target dir")
	if err := parseArgs(fs, args); err != nil {
		return usagef("restore: %v", err)
	}
	if fs.NArg() < 1 {
		return usagef("restore <game>")
	}
	cfg, paths, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	cl, err := e.clientFor(cfg)
	if err != nil {
		return err
	}
	appID, slot, _ := clicfg.GameRef(fs.Arg(0))
	for _, t := range cfg.Tracked {
		if t.App != appID || t.Slot != slot {
			continue
		}
		src := sourceFor(t)
		if *to != "" {
			src = client.Source{Roots: []client.Root{{Key: "restore", Dir: *to}}}
		}
		_, err := cl.Pull(ctx, t.App, t.Slot, *snap, src, stateStore(paths), client.PullOptions{Delete: false})
		return err
	}
	return &ExitError{ExError, fmt.Errorf("game %q not tracked", appID)}
}

func cmdDeleteSnapshot(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("delete-snapshot", flag.ContinueOnError)
	var c common
	c.add(fs)
	if err := parseArgs(fs, args); err != nil || fs.NArg() < 2 {
		return usagef("delete-snapshot <game> <id>")
	}
	cfg, _, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	cl, err := e.clientFor(cfg)
	if err != nil {
		return err
	}
	appID, slot, _ := clicfg.GameRef(fs.Arg(0))
	if !c.yes {
		return &ExitError{ExUsage, fmt.Errorf("refusing without --yes")}
	}
	return cl.DeleteSnapshot(ctx, appID, slot, fs.Arg(1))
}

func cmdDeleteSlot(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("delete-slot", flag.ContinueOnError)
	var c common
	c.add(fs)
	if err := parseArgs(fs, args); err != nil || fs.NArg() < 2 {
		return usagef("delete-slot <app> <slot>")
	}
	cfg, _, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	cl, err := e.clientFor(cfg)
	if err != nil {
		return err
	}
	if !c.yes {
		return &ExitError{ExUsage, fmt.Errorf("refusing without --yes")}
	}
	return cl.DeleteSlot(ctx, fs.Arg(0), fs.Arg(1))
}

func cmdBackups(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("backups", flag.ContinueOnError)
	var c common
	c.add(fs)
	if err := parseArgs(fs, args); err != nil {
		return usagef("backups: %v", err)
	}
	_, paths, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	base := filepath.Join(paths.State, "backups")
	sub := "list"
	if fs.NArg() > 0 {
		sub = fs.Arg(0)
	}
	switch sub {
	case "list":
		_ = filepath.Walk(base, func(p string, i os.FileInfo, err error) error {
			if err == nil && i.IsDir() && p != base {
				rel, _ := filepath.Rel(base, p)
				if strings.Count(rel, string(filepath.Separator)) == 2 {
					fmt.Fprintln(e.Stdout, rel)
				}
			}
			return nil
		})
		return nil
	case "restore":
		cfg, _, err := c.loadConfig(e)
		if err != nil {
			return err
		}
		rest := fs.Args()[1:]
		if len(rest) < 1 {
			return usagef("backups restore <game> [--at STAMP]")
		}
		appID, slot, _ := clicfg.GameRef(rest[0])
		stamp := ""
		if len(rest) > 2 && rest[1] == "--at" {
			stamp = rest[2]
		}
		dir := filepath.Join(base, appID, slot)
		if stamp == "" {
			ents, err := os.ReadDir(dir)
			if err != nil {
				return &ExitError{ExError, fmt.Errorf("no backups for %s/%s", appID, slot)}
			}
			var stamps []string
			for _, en := range ents {
				if en.IsDir() {
					stamps = append(stamps, en.Name())
				}
			}
			sort.Strings(stamps)
			if len(stamps) == 0 {
				return &ExitError{ExError, fmt.Errorf("no backups for %s/%s", appID, slot)}
			}
			stamp = stamps[len(stamps)-1]
		}
		src := filepath.Join(dir, stamp)
		var t *clicfg.Tracked
		for i := range cfg.Tracked {
			if cfg.Tracked[i].App == appID && cfg.Tracked[i].Slot == slot {
				t = &cfg.Tracked[i]
			}
		}
		if t == nil {
			return &ExitError{ExError, fmt.Errorf("game %q not tracked", appID)}
		}
		// Copy each backup file back into its root.
		sr, err := os.OpenRoot(src)
		if err != nil {
			return err
		}
		defer sr.Close()
		n := 0
		for k, d := range t.Roots {
			dr, err := os.OpenRoot(d)
			if err != nil {
				continue
			}
			err = copyRootDir(sr, dr, ".")
			_ = dr.Close()
			if err == nil {
				n++
				_ = k
			}
		}
		fmt.Fprintf(e.Stdout, "restored %d roots from %s\n", n, stamp)
		return nil
	case "prune":
		cfg, _, err := c.loadConfig(e)
		if err != nil {
			return err
		}
		keep := cfg.BackupsKeep
		_ = filepath.Walk(base, func(p string, i os.FileInfo, err error) error {
			if err != nil || !i.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(base, p)
			if strings.Count(rel, string(filepath.Separator)) != 2 {
				return nil
			}
			dir := filepath.Dir(p)
			ents, _ := os.ReadDir(dir)
			var stamps []string
			for _, en := range ents {
				if en.IsDir() {
					stamps = append(stamps, en.Name())
				}
			}
			sort.Strings(stamps)
			for j := 0; j+keep < len(stamps); j++ {
				_ = os.RemoveAll(filepath.Join(dir, stamps[j]))
			}
			return filepath.SkipDir
		})
		return nil
	default:
		return usagef("backups: unknown subcommand %q", sub)
	}
}

func cmdDoctor(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	var c common
	c.add(fs)
	if err := parseArgs(fs, args); err != nil {
		return usagef("doctor: %v", err)
	}
	cfg, paths, err := c.loadConfig(e)
	if err != nil {
		fmt.Fprintf(e.Stdout, "config: %v\n", err)
		return &ExitError{ExError, err}
	}
	ok := true
	if cfg.Server == "" {
		fmt.Fprintln(e.Stdout, "server: not configured")
		ok = false
	} else {
		cl, err := e.clientFor(cfg)
		if err != nil {
			fmt.Fprintf(e.Stdout, "client: %v\n", err)
			ok = false
		} else if _, err := cl.Me(ctx); err != nil {
			fmt.Fprintf(e.Stdout, "auth: %v\n", err)
			ok = false
		} else {
			fmt.Fprintln(e.Stdout, "auth: ok")
		}
	}
	for _, t := range cfg.Tracked {
		for k, d := range t.Roots {
			if _, err := os.Stat(d); err != nil {
				fmt.Fprintf(e.Stdout, "tracked %s/%s root %s missing: %s\n", t.App, t.Slot, k, d)
				ok = false
			}
		}
	}
	if err := os.MkdirAll(paths.State, 0o700); err != nil {
		fmt.Fprintf(e.Stdout, "state dir: %v\n", err)
		ok = false
	}
	if !ok {
		return &ExitError{ExError, fmt.Errorf("doctor found problems")}
	}
	fmt.Fprintln(e.Stdout, "doctor: ok")
	return nil
}

func cmdCompletion(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		return usagef("completion <shell>")
	}
	var b strings.Builder
	switch args[0] {
	case "bash":
		b.WriteString("complete -W '")
		for _, n := range Commands() {
			b.WriteString(n + " ")
		}
		b.WriteString("' savesctl\n")
	case "zsh":
		b.WriteString("#compdef savesctl\n_arguments '1: :(")
		for _, n := range Commands() {
			b.WriteString(n + " ")
		}
		b.WriteString(")'\n")
	case "fish":
		for _, n := range Commands() {
			b.WriteString("complete -c savesctl -f -a " + n + "\n")
		}
	case "powershell":
		b.WriteString("Register-ArgumentCompleter -CommandName savesctl -ScriptBlock { param($w,$c,$p) @(")
		for i, n := range Commands() {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString("'" + n + "'")
		}
		b.WriteString(") }\n")
	default:
		return usagef("unknown shell %q", args[0])
	}
	fmt.Fprint(e.Stdout, b.String())
	return nil
}

// copyRootDir recursively copies files from src root to dst root.
func copyRootDir(src, dst *os.Root, rel string) error {
	return fs.WalkDir(src.FS(), rel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." {
				return dst.MkdirAll(p, 0o755)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		in, err := src.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := dst.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}

func mustIter(it func(func(client.Snapshot) bool), err error) func(func(client.Snapshot) bool) {
	if err != nil || it == nil {
		return func(func(client.Snapshot) bool) {}
	}
	return it
}
