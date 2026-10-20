// SPDX-License-Identifier: 0BSD

package sandbox

import "github.com/prometheus/client_golang/prometheus"

// ReportMetrics registers the sandbox gauges on reg.
func ReportMetrics(reg prometheus.Registerer, r Report) {
	gv := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "saves_sandbox_enforced", Help: "landlock class enforced"}, []string{"class"})
	for cls, on := range map[string]bool{
		"fs": r.FS, "tcp": r.TCP, "udp": r.UDP, "scoped": r.Scoped} {
		v := 0.0
		if on {
			v = 1
		}
		gv.WithLabelValues(cls).Set(v)
	}
	abi := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "saves_sandbox_abi", Help: "landlock abi"})
	abi.Set(float64(r.ABI))
	reg.Register(gv)
	reg.Register(abi)
}
