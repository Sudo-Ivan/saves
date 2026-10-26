// SPDX-License-Identifier: 0BSD

package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
)

type adminTab struct {
	Label, Href string
	Current     bool
}

// adminTabs builds the console sub navigation.
func adminTabs(base, active string) []adminTab {
	list := []struct{ key, label, path string }{
		{"overview", "Overview", "admin"},
		{"users", "Users", "admin/users"},
		{"access", "Access", "admin/access"},
		{"settings", "Settings", "admin/settings"},
		{"audit", "Audit log", "admin/audit"},
		{"security", "Security", "admin/security"},
		{"system", "System", "admin/system"},
	}
	out := make([]adminTab, len(list))
	for i, t := range list {
		out[i] = adminTab{t.label, base + t.path, t.key == active}
	}
	return out
}

// chartPanel is one chart card in the console.
type chartPanel struct {
	Title, Total, Aria, Kind string
	Line                     LineChart
	Bars, Bars2              BarChart
	Empty                    bool
}

type tile struct{ Label, Value, Sub, Href string }

func compact(v float64) string {
	switch {
	case v >= 1e9:
		return trimZero(fmt.Sprintf("%.1fG", v/1e9))
	case v >= 1e6:
		return trimZero(fmt.Sprintf("%.1fM", v/1e6))
	case v >= 1e3:
		return trimZero(fmt.Sprintf("%.1fk", v/1e3))
	}
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return fmt.Sprintf("%.1f", v)
}

func trimZero(s string) string {
	if len(s) > 2 && s[len(s)-3:len(s)-1] == ".0" {
		return s[:len(s)-3] + s[len(s)-1:]
	}
	return s
}

func fmtBytes(v float64) string {
	const u = 1024.0
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for v >= u && i < len(units)-1 {
		v /= u
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", v)
	}
	return trimZero(fmt.Sprintf("%.1f", v)) + " " + units[i]
}

func dayLabel(d int) string {
	return fmt.Sprintf("%02d-%02d", d/100%100, d%100)
}

func seriesVals(rows []meta.StatsRow, f func(meta.StatsRow) int64) ([]float64, []string, int64) {
	v := make([]float64, len(rows))
	l := make([]string, len(rows))
	var sum int64
	for i, r := range rows {
		x := f(r)
		v[i] = float64(x)
		l[i] = dayLabel(r.Day)
		sum += x
	}
	return v, l, sum
}

func buildPanels(rows []meta.StatsRow) []chartPanel {
	var out []chartPanel
	line := func(title, aria string, f func(meta.StatsRow) int64, ff func(float64) string, gauge bool) {
		v, l, sum := seriesVals(rows, f)
		total := ff(float64(sum))
		if gauge && len(v) > 0 {
			total = ff(v[len(v)-1])
		}
		lc := NewLineChart(v, l, 360, 150, ff)
		out = append(out, chartPanel{Title: title, Total: total, Aria: aria, Kind: "line", Line: lc, Empty: lc.Empty})
	}
	bars := func(title, aria string, f func(meta.StatsRow) int64, ff func(float64) string) {
		v, l, sum := seriesVals(rows, f)
		bc := NewBarChart(v, l, 360, 150, ff)
		out = append(out, chartPanel{Title: title, Total: ff(float64(sum)), Aria: aria, Kind: "bars", Bars: bc, Empty: bc.Empty})
	}
	stacked := func(title, aria string, fa, fb func(meta.StatsRow) int64, ff func(float64) string) {
		a, l, sa := seriesVals(rows, fa)
		b, _, sb := seriesVals(rows, fb)
		b1, b2 := StackedBars(a, b, l, 360, 150, ff)
		sum := make([]float64, len(a))
		for i := range a {
			sum[i] = a[i]
			if i < len(b) {
				sum[i] += b[i]
			}
		}
		ref := NewBarChart(sum, l, 360, 150, ff)
		b1.YTicks, b1.XTicks = ref.YTicks, ref.XTicks
		out = append(out, chartPanel{Title: title, Total: ff(float64(sa)) + " / " + ff(float64(sb)), Aria: aria,
			Kind: "stacked", Bars: b1, Bars2: b2, Empty: b1.Empty && b2.Empty})
	}
	line("Requests", "Requests per day, last 30 days", func(r meta.StatsRow) int64 { return r.Requests }, compact, false)
	bars("Server errors", "Responses with a 5xx status per day, last 30 days", func(r meta.StatsRow) int64 { return r.Errors5xx }, compact)
	line("Active users", "Distinct active users per day, last 30 days", func(r meta.StatsRow) int64 { return r.ActiveUsers }, compact, false)
	bars("Sign-ups", "New accounts per day, last 30 days", func(r meta.StatsRow) int64 { return r.Signups }, compact)
	stacked("Sign-ins, ok and failed", "Successful and failed sign-ins per day, last 30 days",
		func(r meta.StatsRow) int64 { return r.LoginsOK }, func(r meta.StatsRow) int64 { return r.LoginsFailed }, compact)
	bars("Snapshots committed", "Snapshots committed per day, last 30 days", func(r meta.StatsRow) int64 { return r.Snapshots }, compact)
	stacked("Transfer, in and out", "Bytes received and sent per day, last 30 days",
		func(r meta.StatsRow) int64 { return r.BytesIn }, func(r meta.StatsRow) int64 { return r.BytesOut }, fmtBytes)
	line("Storage used", "Total stored bytes per day, last 30 days", func(r meta.StatsRow) int64 { return r.Storage }, fmtBytes, true)
	line("Total users", "Total accounts per day, last 30 days", func(r meta.StatsRow) int64 { return r.Users }, compact, true)
	return out
}

type adminOverview struct {
	Tabs                              []adminTab
	Tiles                             []tile
	Panels                            []chartPanel
	SparkReq, SparkErr                LineChart
	LiveReq, LiveErr, LiveIn, LiveOut string
	Audit                             []meta.AuditEvent
	TopUsers                          []meta.AdminUserRow
	TopApps                           []meta.AppBytes
	Crit, Warn, Info                  int
	Critical                          []Finding
	Refresh                           int
	Notice                            string
}

func (s *Server) whAdmin(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	d := s.AdminDashboard(r.Context())
	base := wv.web.link
	ov := adminOverview{Tabs: adminTabs(base, "overview"), Audit: d.RecentAudit, TopUsers: d.TopUsers, TopApps: d.TopApps}
	var activeToday int64
	if n := len(d.Series); n > 0 {
		activeToday = d.Series[n-1].ActiveUsers
	}
	t := d.Totals
	ov.Tiles = []tile{
		{"Users", compact(float64(t.Users)), "", base + "admin/users"},
		{"Active today", compact(float64(activeToday)), "distinct users", ""},
		{"Storage used", fmtBytes(float64(t.UsedBytes)), compact(float64(t.Apps)) + " apps", ""},
		{"Snapshots", compact(float64(t.Snapshots)), compact(float64(t.Slots)) + " slots", ""},
		{"Active tokens", compact(float64(t.ActiveTokens)), "", ""},
		{"Active sessions", compact(float64(t.ActiveSessions)), "", ""},
		{"Pending approval", compact(float64(d.Pending)), "", base + "admin/users?state=pending"},
		{"Banned", compact(float64(d.Banned)), "", base + "admin/users?state=banned"},
		{"Locked usernames", strconv.Itoa(d.LockedUsers), "", ""},
		{"IP blocks", strconv.Itoa(d.IPBlocks), "active", ""},
	}
	ov.Panels = buildPanels(d.Series)
	var req, errs, in, out []float64
	var sr, se, si, so int64
	for _, m := range d.Live {
		req = append(req, float64(m.Requests))
		errs = append(errs, float64(m.Errors))
		sr += m.Requests
		se += m.Errors
		si += m.BytesIn
		so += m.BytesOut
	}
	_, _ = in, out
	ov.SparkReq = NewSparkline(req, 240, 48)
	ov.SparkErr = NewSparkline(errs, 240, 48)
	ov.LiveReq, ov.LiveErr, ov.LiveIn, ov.LiveOut = compact(float64(sr)), compact(float64(se)), fmtBytes(float64(si)), fmtBytes(float64(so))
	for _, f := range s.SecurityCheckup(r.Context()) {
		switch f.Severity {
		case "critical":
			ov.Crit++
			ov.Critical = append(ov.Critical, f)
		case "warn":
			ov.Warn++
		case "info":
			ov.Info++
		}
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("refresh")); err == nil && (v == 15 || v == 30 || v == 60) {
		ov.Refresh = v
	}
	wv.render("admin", 200, ov)
}

type adminSystem struct {
	Tabs          []adminTab
	Info          SysInfo
	Heap          string
	Uptime        string
	Started       string
	DBSize        string
	DiskFree      string
	DiskTotal     string
	DiskUsedPct   int
	HasDisk       bool
	Fsck, GC      opState
	BackupEnabled bool
	BackupDir     string
	Notice, Error string
}

func (s *Server) whAdminSystem(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	info := s.SysInfo()
	v := adminSystem{Tabs: adminTabs(wv.web.link, "system"), Info: info, Fsck: s.FsckState(), GC: s.GCState(),
		BackupEnabled: s.BackupEnabled(), BackupDir: s.Cfg.Admin.BackupDir,
		Uptime: info.Uptime.Round(time.Second).String(), Started: info.StartedAt.UTC().Format("2006-01-02 15:04 UTC")}
	v.DBSize = fmtBytes(float64(info.MetaDBBytes))
	v.Heap = fmtBytes(float64(info.HeapAlloc))
	if s.Cfg.Storage.Blob.Driver == "fs" {
		if free, total, ok := diskUsage(s.Cfg.Storage.Blob.FS.Root); ok && total > 0 {
			v.HasDisk = true
			v.DiskFree, v.DiskTotal = fmtBytes(float64(free)), fmtBytes(float64(total))
			v.DiskUsedPct = int(100 - free*100/total)
		}
	}
	switch r.URL.Query().Get("n") {
	case "gc":
		v.Notice = "Garbage collection finished."
	case "gcfail":
		v.Error = "Garbage collection failed. See the server log."
	case "fsck":
		v.Notice = "Integrity check started."
	case "fsckbusy":
		v.Error = "An integrity check is already running."
	case "backup":
		v.Notice = "Database backup written."
	case "backupfail":
		v.Error = "The backup failed. See the server log."
	}
	wv.render("admin_system", 200, v)
}

type findingGroup struct {
	Severity, Label string
	Items           []Finding
}

type adminSecurity struct {
	Tabs   []adminTab
	Groups []findingGroup
	OK     bool
}

func (s *Server) whAdminSecurity(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() {
		return
	}
	groups := []findingGroup{{"critical", "Fix now", nil}, {"warn", "Worth fixing", nil}, {"info", "For your information", nil}}
	any := false
	for _, f := range s.SecurityCheckup(r.Context()) {
		for i := range groups {
			if groups[i].Severity == f.Severity {
				groups[i].Items = append(groups[i].Items, f)
				any = true
			}
		}
	}
	var keep []findingGroup
	for _, g := range groups {
		if len(g.Items) > 0 {
			keep = append(keep, g)
		}
	}
	wv.render("admin_security", 200, adminSecurity{Tabs: adminTabs(wv.web.link, "security"), Groups: keep, OK: !any})
}

func (s *Server) whAdminFsck(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	n := "fsck"
	if !s.RunFsck() {
		n = "fsckbusy"
	}
	s.audit(r.Context(), wv.sess.UserID, "admin.fsck", "system", "", "")
	http.Redirect(w, r, wv.web.link+"admin/system?n="+n, http.StatusSeeOther) // #nosec G710 -- fixed route
}

func (s *Server) whAdminBackup(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAdmin() || !wv.parseForm() || !wv.requireCSRF() {
		return
	}
	n := "backup"
	if _, err := s.RunBackupMeta(r.Context()); err != nil {
		s.Log.Error("admin backup", "err", err)
		n = "backupfail"
	}
	s.audit(r.Context(), wv.sess.UserID, "admin.backup", "system", "", "")
	http.Redirect(w, r, wv.web.link+"admin/system?n="+n, http.StatusSeeOther) // #nosec G710 -- fixed route
}
