// Command dashboard emits the ts1p Grafana dashboard as a bare dashboard JSON
// model, built with the Grafana Foundation SDK. It is a build-time code
// generator: a Nix derivation (or anyone not using Nix) runs it and captures
// stdout as ts1p.json for file-based Grafana provisioning.
//
// ts1p runs as multiple stateless instances behind an HA Tailscale Service, so
// the dashboard is built around two template variables — $job and (multi-value)
// $instance — that every query filters on. With "All" instances selected a panel
// shows the fleet; select one and the same panel drills into that box.
//
// The dashboard references its Prometheus source through a $datasource variable
// rather than a hardcoded UID, so it drops into any Grafana that scrapes ts1p.
//
// Only metrics on the scraped /metrics surface are charted. Tailscale/tsnet
// clientmetrics live on the loopback /debug/varz (dev/loopback only), never the
// tailnet /metrics a Prometheus job scrapes, so there are no panels for them.
package main

import (
	"github.com/grafana/grafana-foundation-sdk/go/common"
	"github.com/grafana/grafana-foundation-sdk/go/dashboard"
	"github.com/grafana/grafana-foundation-sdk/go/prometheus"
	"github.com/grafana/grafana-foundation-sdk/go/stat"
	"github.com/grafana/grafana-foundation-sdk/go/table"
	"github.com/grafana/grafana-foundation-sdk/go/timeseries"
	"github.com/grafana/grafana-foundation-sdk/go/units"
)

// datasourceVar is the name of the datasource template variable; panels point at
// "${datasourceVar}" so the viewer's Grafana picks the concrete datasource.
const datasourceVar = "datasource"

// sel is the label matcher every query carries. $job and $instance are template
// variables; $instance is multi-value with an "All" option, so "All" → the whole
// fleet, one selected → that instance. Aggregating panels wrap this in sum(...);
// per-instance panels group by (instance) and legend on {{instance}}.
const sel = `{job=~"$job", instance=~"$instance"}`

// promDS references the datasource selected by the $datasource variable.
func promDS() common.DataSourceRef {
	return common.DataSourceRef{
		Type: new("prometheus"),
		Uid:  new("${" + datasourceVar + "}"),
	}
}

// query is a Prometheus range target with an expression and legend.
func query(expr, legend string) *prometheus.DataqueryBuilder {
	return prometheus.NewDataqueryBuilder().Expr(expr).LegendFormat(legend)
}

// timeseriesPanel is the common shape for graph panels: half-width, a unit, a
// description (the ⓘ tooltip), and one or more Prometheus targets.
//
// Every panel shows a table legend with the last and max of each series (so a
// fleet of instances is readable at a glance and sortable by column) and a
// multi-series tooltip sorted high-to-low (so hovering compares all instances at
// the cursor). Without these the SDK default hides the legend entirely.
func timeseriesPanel(title, description, unit string, targets ...*prometheus.DataqueryBuilder) *timeseries.PanelBuilder {
	p := timeseries.NewPanelBuilder().
		Title(title).
		Description(description).
		Unit(unit).
		Datasource(promDS()).
		Span(12).
		Height(8).
		FillOpacity(10).
		Legend(common.NewVizLegendOptionsBuilder().
			ShowLegend(true).
			DisplayMode(common.LegendDisplayModeTable).
			Placement(common.LegendPlacementBottom).
			Calcs([]string{"lastNotNull", "max"})).
		Tooltip(common.NewVizTooltipOptionsBuilder().
			Mode(common.TooltipDisplayModeMulti).
			Sort(common.SortOrderDescending))
	for _, t := range targets {
		p = p.WithTarget(t)
	}

	return p
}

// statPanel is a single-number tile with a unit, a description, and one target.
func statPanel(title, description, unit string, target *prometheus.DataqueryBuilder) *stat.PanelBuilder {
	return stat.NewPanelBuilder().
		Title(title).
		Description(description).
		Unit(unit).
		Datasource(promDS()).
		Span(6).
		Height(4).
		ColorMode(common.BigValueColorModeValue).
		GraphMode(common.BigValueGraphModeArea).
		ReduceOptions(common.NewReduceDataOptionsBuilder().Calcs([]string{"lastNotNull"})).
		WithTarget(target)
}

// freshnessThresholds colour a "seconds since last X" tile: green under 5m, amber
// 5–15m, red past 15m — a warmer that has not succeeded in 15m is serving stale.
func freshnessThresholds() *dashboard.ThresholdsConfigBuilder {
	return dashboard.NewThresholdsConfigBuilder().
		Mode(dashboard.ThresholdsModeAbsolute).
		Steps([]dashboard.Threshold{
			{Value: nil, Color: "green"},
			{Value: new(300.0), Color: "yellow"},
			{Value: new(900.0), Color: "red"},
		})
}

// queryVar is a Prometheus label_values() template variable.
func queryVar(name, label, expr string) *dashboard.QueryVariableBuilder {
	return dashboard.NewQueryVariableBuilder(name).
		Label(label).
		Datasource(promDS()).
		Query(dashboard.StringOrMap{String: new(expr)}).
		Refresh(dashboard.VariableRefreshOnTimeRangeChanged).
		Sort(dashboard.VariableSortAlphabeticalAsc)
}

// versionTable renders ts1p_runtime_versions_info as an instant table, one row
// per instance, so version drift across the fleet is visible at a glance. The
// organize transformation drops the noise columns the raw instant query carries
// (Time, __name__, the constant Value=1, job) and orders instance first, leaving
// a clean instance→versions grid. Filterable() lets the viewer search/sort it.
func versionTable() *table.PanelBuilder {
	return table.NewPanelBuilder().
		Title("Runtime versions").
		Description("Build/runtime versions per instance, from ts1p_runtime_versions_info. Rows that disagree mean the fleet is mid-rollout or a box is stuck on an old build.").
		Datasource(promDS()).
		Span(24).
		Height(6).
		Filterable(true).
		WithTarget(prometheus.NewDataqueryBuilder().
			Expr(`ts1p_runtime_versions_info` + sel).
			Format(prometheus.PromQueryFormatTable).
			Instant()).
		WithTransformation(dashboard.DataTransformerConfig{
			Id: "organize",
			Options: map[string]any{
				"excludeByName": map[string]any{
					"Time": true, "__name__": true, "Value": true, "job": true,
				},
				"indexByName": map[string]any{
					"instance": 0, "go": 1, "wazero": 2, "extism": 3, "onepassword": 4,
				},
				"renameByName": map[string]any{},
			},
		})
}

// buildDashboard assembles the full ts1p dashboard. Build() schema-validates, so
// a malformed panel fails here (and thus fails the generating derivation).
//
// We emit the v1 dashboard model on purpose: it is what file-based Grafana
// provisioning consumes and works on Grafana >= 10. dashboardv2 is the Grafana
// 12 app-platform schema and is not portable to the generic instances this
// dashboard targets — hence the staticcheck deprecation is knowingly ignored.
//
//nolint:staticcheck // v1 model required for portable file-based provisioning
func buildDashboard() (dashboard.Dashboard, error) {
	return dashboard.NewDashboardBuilder("ts1p").
		Uid("ts1p").
		Description("ts1p secrets server: cache health, 1Password backend faults, and Go runtime/process health. Use $job and $instance (multi-value, includes All) to scope from the whole fleet down to a single instance.").
		Tags([]string{"ts1p", "tailscale", "secrets", "generated"}).
		Refresh("30s").
		Time("now-6h", "now").
		Timezone(common.TimeZoneBrowser).
		WithVariable(
			dashboard.NewDatasourceVariableBuilder(datasourceVar).
				Label("Data source").
				Type("prometheus"),
		).
		WithVariable(
			queryVar("job", "Job", `label_values(go_goroutines, job)`),
		).
		WithVariable(
			queryVar("instance", "Instance", `label_values(go_goroutines{job=~"$job"}, instance)`).
				Multi(true).
				IncludeAll(true),
		).

		// Row 1 — Overview: headline health across the selected scope.
		WithRow(dashboard.NewRowBuilder("Overview")).
		WithPanel(
			statPanel("Instances up", "Number of scraped ts1p instances currently up (sum of the scrape 'up' series). Drops below the expected count = a box is down or unscrapable.",
				units.Short, query(`sum(up`+sel+`)`, "up")).
				GraphMode(common.BigValueGraphModeNone),
		).
		WithPanel(
			statPanel("Cache freshness", "Seconds since the newest successful cache warm across the scope. Climbs when 1Password refreshes fail; green <5m, amber <15m, red past 15m.",
				units.Seconds, query(`time() - max(ts1p_cache_last_warm_timestamp_seconds`+sel+`)`, "age")).
				Thresholds(freshnessThresholds()).
				ColorMode(common.BigValueColorModeBackground),
		).
		WithPanel(
			statPanel("Stale reads/s", "Rate of reads served from a stale cache because 1Password was unreachable. Any sustained value >0 means clients are getting old secrets — investigate the backend.",
				units.OpsPerSecond, query(`sum(rate(ts1p_cache_stale_served_total`+sel+`[5m]))`, "stale")),
		).
		WithPanel(
			statPanel("1Password faults/s", "Combined rate of all 1Password SDK faults (OOB, ctx-canceled, core-timeout, rate-limited, auth-failed). The per-kind split is in the 1Password backend row.",
				units.OpsPerSecond, query(opFaultRateExpr, "faults")),
		).
		WithPanel(versionTable()).

		// Row 2 — Cache health: the warmer keeps the cache ahead of 1Password.
		WithRow(dashboard.NewRowBuilder("Cache health")).
		WithPanel(
			timeseriesPanel("Warm success vs fail", "Background cache-refresh rate per instance: successful warms vs failures. Sustained failures precede staleness.",
				units.OpsPerSecond,
				query(`sum by (instance) (rate(ts1p_cache_warm_total`+sel+`[5m]))`, "{{instance}} ok"),
				query(`sum by (instance) (rate(ts1p_cache_warm_fail_total`+sel+`[5m]))`, "{{instance}} fail")),
		).
		WithPanel(
			timeseriesPanel("Time since last successful warm", "Seconds since each instance last warmed successfully. A line climbing without resetting is a warmer that has stopped succeeding — the alertable staleness signal.",
				units.Seconds,
				query(`time() - ts1p_cache_last_warm_timestamp_seconds`+sel, "{{instance}}")),
		).
		WithPanel(
			timeseriesPanel("Stale reads served", "Per-instance rate of stale-while-revalidate reads (1Password was unavailable). Should sit at zero; any sustained value means degraded reads.",
				units.OpsPerSecond,
				query(`sum by (instance) (rate(ts1p_cache_stale_served_total`+sel+`[5m]))`, "{{instance}}")),
		).

		// Row 3 — 1Password backend: the WASM core's failure modes.
		WithRow(dashboard.NewRowBuilder("1Password backend")).
		WithPanel(
			timeseriesPanel("Faults by type", "Rate of 1Password SDK faults across the scope, split by kind. rate-limited = hitting the service-account quota; auth-failed = credential problem; out-of-bounds/core-timeout = a wedged WASM core (triggers a process recycle). The full WASM stack frame of the most recent fault is in the service logs.",
				units.OpsPerSecond,
				query(`sum(rate(ts1p_op_oob_total`+sel+`[5m]))`, "out-of-bounds"),
				query(`sum(rate(ts1p_op_ctx_canceled_total`+sel+`[5m]))`, "ctx-canceled"),
				query(`sum(rate(ts1p_op_core_timeout_total`+sel+`[5m]))`, "core-timeout"),
				query(`sum(rate(ts1p_op_rate_limited_total`+sel+`[5m]))`, "rate-limited"),
				query(`sum(rate(ts1p_op_auth_failed_total`+sel+`[5m]))`, "auth-failed")),
		).
		WithPanel(
			timeseriesPanel("Time since last fault, by class/op", "Seconds since the last 1Password fault of each class/operation (from ts1p_op_last_fault_timestamp_seconds). Shows which failure modes are recent versus long-dormant; a freshly-dropping line is an active problem.",
				units.Seconds,
				query(`time() - max by (class, op) (ts1p_op_last_fault_timestamp_seconds`+sel+`)`, "{{class}} / {{op}}")),
		).

		// Row 4 — Go runtime & process: standard saturation/health signals.
		WithRow(dashboard.NewRowBuilder("Go runtime & process")).
		WithPanel(
			timeseriesPanel("Goroutines", "Live goroutines per instance. A monotonic climb is a goroutine leak; a spike tracks in-flight work.",
				units.Short,
				query(`go_goroutines`+sel, "{{instance}}")),
		).
		WithPanel(
			timeseriesPanel("Memory: RSS & heap in-use", "Resident set (what the OS accounts) and Go heap in-use, per instance. RSS is the number that gets the process OOM-killed.",
				units.BytesIEC,
				query(`process_resident_memory_bytes`+sel, "{{instance}} rss"),
				query(`go_memstats_heap_inuse_bytes`+sel, "{{instance}} heap")),
		).
		WithPanel(
			timeseriesPanel("CPU usage", "CPU seconds burned per second per instance (1.0 = one full core). Tracks load and catches a spinning core.",
				units.Short,
				query(`sum by (instance) (rate(process_cpu_seconds_total`+sel+`[5m]))`, "{{instance}}")),
		).
		WithPanel(
			timeseriesPanel("GC pause (p75)", "75th-percentile stop-the-world GC pause per instance. Rising pauses mean GC pressure — usually allocation churn.",
				units.Seconds,
				query(`go_gc_duration_seconds{job=~"$job", instance=~"$instance", quantile="0.75"}`, "{{instance}}")),
		).
		WithPanel(
			timeseriesPanel("File descriptors (used/max)", "Open FDs as a fraction of the limit, per instance. Approaching 1.0 means the process is about to fail accepts — a leak or an undersized ulimit.",
				units.Percent,
				query(`process_open_fds`+sel+` / process_max_fds`+sel, "{{instance}}")).
				Min(0).Max(1),
		).
		WithPanel(
			timeseriesPanel("Uptime", "Time since process start, per instance. A sudden drop to ~0 is a restart or crash (e.g. a WASM-core recycle).",
				units.Seconds,
				query(`time() - process_start_time_seconds`+sel, "{{instance}}")),
		).
		Build()
}

// opFaultRateExpr is the combined rate of every 1Password fault counter, for the
// Overview headline tile. The per-kind breakdown lives in the backend row.
const opFaultRateExpr = `sum(rate(ts1p_op_oob_total` + sel + `[5m])) + ` +
	`sum(rate(ts1p_op_ctx_canceled_total` + sel + `[5m])) + ` +
	`sum(rate(ts1p_op_core_timeout_total` + sel + `[5m])) + ` +
	`sum(rate(ts1p_op_rate_limited_total` + sel + `[5m])) + ` +
	`sum(rate(ts1p_op_auth_failed_total` + sel + `[5m]))`
