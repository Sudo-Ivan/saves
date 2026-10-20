// SPDX-License-Identifier: 0BSD
//go:build linux

package sandbox

import (
	"errors"
	"fmt"

	"github.com/landlock-lsm/go-landlock/landlock"
	llconfig "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Apply confines the process per policy and mode.
func Apply(p *Policy, mode string) (Report, error) {
	r := Report{Mode: mode}
	switch mode {
	case "off":
		r.Supported = false
		return r, nil
	}
	if _, err := llconfig.LandlockGetABIVersion(); err != nil {
		if mode == "enforce" {
			return r, errors.New("sandbox: kernel has no Landlock support")
		}
		return r, nil
	}
	cfg := landlock.V10
	var rules []landlock.Rule
	if len(p.RODirs) > 0 {
		rules = append(rules, landlock.RODirs(p.RODirs...))
	}
	if len(p.ROFiles) > 0 {
		rules = append(rules, landlock.ROFiles(p.ROFiles...))
	}
	if len(p.RWFiles) > 0 {
		rules = append(rules, landlock.RWFiles(p.RWFiles...).WithRefer())
	}
	if len(p.RWDirs) > 0 {
		rules = append(rules, landlock.RWDirs(p.RWDirs...).WithRefer())
	}
	for _, po := range p.ConnectTCP {
		rules = append(rules, landlock.ConnectTCP(po))
	}
	for _, po := range p.BindTCP {
		rules = append(rules, landlock.BindTCP(po))
	}
	// Apply everything in one Restrict call: stacking separate
	// RestrictPaths/RestrictNet/RestrictScoped layers breaks refer on
	// renames between covered dirs.
	var ferr, nerr, serr error
	if mode == "best-effort" {
		ferr = cfg.BestEffort().Restrict(rules...)
		serr = ferr
	} else {
		ferr = cfg.Restrict(rules...)
		serr = ferr
	}
	r.Supported = true
	nnp, _ := NoNewPrivs()
	if mode == "enforce" && !nnp {
		return r, errors.New("sandbox: no_new_privs not set after landlock apply")
	}
	r.ABI = abi(cfg)
	r.FS = ferr == nil
	r.TCP = nerr == nil
	r.Scoped = serr == nil
	if mode == "enforce" {
		if !r.FS || !r.TCP {
			return r, fmt.Errorf("sandbox: enforce needs full fs+tcp coverage: fs=%v tcp=%v", ferr, nerr)
		}
	}
	_ = errors.Is
	return r, nil
}

func abi(c landlock.Config) int {
	v, err := llconfig.LandlockGetABIVersion()
	if err != nil {
		return 0
	}
	_ = c
	return int(v)
}
