import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api/endpoints";
import { IPDetail, FlowAnalysis } from "../api/types";
import { ArrowLeft, Target, ShieldAlert, Flag, Brain, Split } from "lucide-react";
import { cn } from "../utils/cn";

export function IPDetailPage() {
    const { ip } = useParams<{ ip: string }>();
    const [data, setData] = useState<IPDetail | null>(null);
    const [flow, setFlow] = useState<FlowAnalysis | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!ip) return;
        setLoading(true);
        setError(null);
        
        Promise.all([
            api.ipDetail(ip, 24),
            api.flowAnalysis(ip)
        ])
        .then(([detailData, flowData]) => {
            setData(detailData);
            setFlow(flowData);
        })
        .catch((err) => {
            setError(err instanceof Error ? err.message : "Failed to load IP detail");
        })
        .finally(() => setLoading(false));
    }, [ip]);

    if (loading) return (
        <div className="flex items-center justify-center h-64">
            <div className="text-sm font-medium animate-pulse" style={{ color: "var(--text-muted)" }}>
                Loading IP profiles & flow sequences…
            </div>
        </div>
    );
    if (error) return (
        <div className="soc-panel p-8 text-center text-red-500 font-semibold border-red-100 bg-red-50/20">
            Error loading IP details: {error}
        </div>
    );
    if (!data) return (
        <div className="soc-panel p-8 text-center" style={{ color: "var(--text-muted)" }}>
            IP profile not found.
        </div>
    );

    return (
        <div className="space-y-6">
            {/* Back header */}
            <div className="flex items-center gap-4">
                <Link to="/alerts">
                    <button
                        className="p-2.5 rounded-xl border transition-colors hover:bg-gray-50"
                        style={{ borderColor: "var(--border-default)" }}
                    >
                        <ArrowLeft className="h-4.5 w-4.5" style={{ color: "var(--text-secondary)" }} />
                    </button>
                </Link>
                <div>
                    <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>
                        IP Profile: {data.remote_ip}
                    </h1>
                    <p className="text-sm mt-0.5" style={{ color: "var(--text-muted)" }}>
                        Contextual risk signals and behavior analysis
                    </p>
                </div>
            </div>

            {/* KPI grid */}
            <div className="grid gap-4 md:grid-cols-4">
                <div className="soc-panel p-5 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Total Requests (24h)</span>
                        <Target className="h-4 w-4" style={{ color: "var(--purple-dark)" }} />
                    </div>
                    <div className="text-2xl font-bold mt-2" style={{ color: "var(--text-primary)" }}>{data.total_events_24h}</div>
                </div>

                <div className="soc-panel p-5 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Session Count</span>
                        <Split className="h-4 w-4" style={{ color: "var(--purple-mid)" }} />
                    </div>
                    <div className="text-2xl font-bold mt-2" style={{ color: "var(--text-primary)" }}>{flow?.session_count ?? 1}</div>
                </div>

                <div className="soc-panel p-5 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Behavior Flags</span>
                        <Flag className="h-4 w-4" style={{ color: "var(--text-muted)" }} />
                    </div>
                    <div className="text-2xl font-bold mt-2" style={{ color: "var(--text-primary)" }}>{data.triggered_flags.length}</div>
                </div>

                <div className="soc-panel p-5 flex flex-col justify-between">
                    <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Recent Alerts</span>
                        <ShieldAlert className="h-4 w-4" style={{ color: data.recent_alerts.length > 0 ? "var(--sev-high)" : "var(--text-muted)" }} />
                    </div>
                    <div className={cn("text-2xl font-bold mt-2", data.recent_alerts.length > 0 && "text-red-500")} style={data.recent_alerts.length > 0 ? { color: "var(--sev-critical)" } : { color: "var(--text-primary)" }}>
                        {data.recent_alerts.length}
                    </div>
                </div>
            </div>

            {/* Workflow Violations Section */}
            {flow && flow.violations && flow.violations.length > 0 && (
                <div className="soc-panel p-6 border-red-200 bg-red-50/20 space-y-4">
                    <div className="flex items-center gap-2">
                        <div className="p-1 rounded bg-red-100 text-red-600">
                            <ShieldAlert className="w-5 h-5" />
                        </div>
                        <h2 className="text-base font-extrabold text-red-800">
                            ⚠️ Workflow Engine violations detected
                        </h2>
                    </div>
                    <div className="grid gap-4 sm:grid-cols-2">
                        {flow.violations.map((violation, idx) => (
                            <div key={idx} className="p-4 rounded-xl bg-white border border-red-100 space-y-2">
                                <div className="flex items-center justify-between">
                                    <span className="font-bold text-sm text-red-800">{violation.name}</span>
                                    <span className={cn(
                                        "badge",
                                        violation.severity === "CRITICAL" ? "badge-critical" :
                                        violation.severity === "HIGH" ? "badge-high" : "badge-medium"
                                    )}>
                                        {violation.severity}
                                    </span>
                                </div>
                                <p className="text-xs text-gray-600 leading-relaxed">{violation.evidence}</p>
                                {violation.sequence && violation.sequence.length > 0 && (
                                    <div className="pt-1.5 space-y-1">
                                        <p className="text-[10px] font-bold text-gray-500 uppercase">Violation Path Sequence:</p>
                                        <div className="flex flex-wrap items-center gap-1 font-mono text-[10px] text-gray-600">
                                            {violation.sequence.map((step, sIdx) => (
                                                <span key={sIdx} className="flex items-center gap-1">
                                                    {sIdx > 0 && <span className="text-gray-400">→</span>}
                                                    <span className="px-1.5 py-0.5 rounded bg-gray-100 border border-gray-200 font-semibold">{step}</span>
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Behavioral analysis & details */}
            <div className="grid gap-6 md:grid-cols-2">
                
                {/* Left side: Behavior Flags and Alerts */}
                <div className="space-y-6">
                    {/* Behavior Flags */}
                    <div className="soc-panel">
                        <div className="px-6 py-4 border-b" style={{ borderColor: "var(--border-default)" }}>
                            <h2 className="text-sm font-extrabold" style={{ color: "var(--text-primary)" }}>Behavior Profiler Flags</h2>
                        </div>
                        <div className="p-6">
                            {data.triggered_flags.length === 0 ? (
                                <div className="text-sm" style={{ color: "var(--text-muted)" }}>No behavioral anomalies flagged in the last 24h.</div>
                            ) : (
                                <div className="space-y-3">
                                    {data.triggered_flags.map((flag, idx) => (
                                        <div key={idx} className="flex items-center justify-between border-b pb-2.5 last:border-0 last:pb-0" style={{ borderColor: "var(--border-default)" }}>
                                            <span className="font-mono text-xs font-semibold px-2 py-1 rounded bg-[var(--bg-page)]" style={{ color: "var(--purple-dark)" }}>{flag.flag_id}</span>
                                            <span className={cn(
                                                "badge",
                                                flag.severity === "CRITICAL" ? "badge-critical" :
                                                flag.severity === "HIGH" ? "badge-high" :
                                                flag.severity === "MEDIUM" ? "badge-medium" : "badge-low"
                                            )}>
                                                {flag.severity}
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Alerts History */}
                    <div className="soc-panel">
                        <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: "var(--border-default)" }}>
                            <h2 className="text-sm font-extrabold" style={{ color: "var(--text-primary)" }}>SOC Alerts (24h)</h2>
                            <span className="badge badge-purple">{data.recent_alerts.length}</span>
                        </div>
                        <div className="p-0">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th style={{ paddingLeft: 24 }}>Severity</th>
                                        <th style={{ paddingRight: 24 }}>Triggered Rule</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {data.recent_alerts.length === 0 ? (
                                        <tr>
                                            <td colSpan={2} className="text-center font-medium py-6" style={{ color: "var(--text-muted)" }}>No security alerts recorded.</td>
                                        </tr>
                                    ) : (
                                        data.recent_alerts.map((a, i) => (
                                            <tr key={i}>
                                                <td style={{ paddingLeft: 24 }}>
                                                    <span className={cn(
                                                        "badge",
                                                        a.severity === "CRITICAL" ? "badge-critical" :
                                                        a.severity === "HIGH" ? "badge-high" :
                                                        a.severity === "MEDIUM" ? "badge-medium" : "badge-low"
                                                    )}>
                                                        {a.severity}
                                                    </span>
                                                </td>
                                                <td className="text-sm font-medium" style={{ paddingRight: 24, color: "var(--text-primary)" }}>
                                                    {a.title}
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                {/* Right side: Session Flow sequences */}
                <div className="soc-panel flex flex-col">
                    <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: "var(--border-default)" }}>
                        <div className="flex items-center gap-2">
                            <Brain className="w-4.5 h-4.5" style={{ color: "var(--purple-dark)" }} />
                            <h2 className="text-sm font-extrabold" style={{ color: "var(--text-primary)" }}>Session Request Flow Sequence</h2>
                        </div>
                        <span className="text-xs font-semibold px-2 py-0.5 rounded bg-[var(--bg-page)]" style={{ color: "var(--purple-dark)" }}>
                            Live Session Sequence
                        </span>
                    </div>
                    <div className="p-6 flex-1 overflow-y-auto max-h-[500px]">
                        {!flow || !flow.recent_sequence || flow.recent_sequence.length === 0 ? (
                            <div className="text-sm text-center py-10" style={{ color: "var(--text-muted)" }}>
                                No HTTP workflow history recorded.
                            </div>
                        ) : (
                            <div className="relative border-l pl-5 space-y-5 font-mono text-xs" style={{ borderColor: "var(--border-default)" }}>
                                {flow.recent_sequence.map((step, idx) => (
                                    <div key={idx} className="relative group">
                                        {/* Timeline Dot */}
                                        <div className="absolute -left-[26px] top-1.5 w-3 h-3 rounded-full border bg-white transition-colors group-hover:bg-[var(--purple-mid)]"
                                             style={{ borderColor: "var(--purple-mid)" }}
                                        />
                                        <div className="space-y-1">
                                            <div className="flex items-center justify-between">
                                                <span className={cn(
                                                    "font-bold px-1.5 py-0.5 rounded text-[10px]",
                                                    step.method === "POST" ? "bg-blue-100 text-blue-800" :
                                                    step.method === "GET" ? "bg-green-100 text-green-800" :
                                                    "bg-yellow-100 text-yellow-800"
                                                )}>{step.method}</span>
                                                <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                                                    {new Date(step.timestamp).toLocaleTimeString()}
                                                </span>
                                            </div>
                                            <p className="font-semibold select-all font-mono-soc text-xs truncate max-w-[280px]" style={{ color: "var(--text-primary)" }}>{step.path}</p>
                                            <div className="flex items-center gap-1.5">
                                                <span className={cn(
                                                    "text-[10px] font-bold",
                                                    step.status >= 400 ? "text-red-500" : "text-green-600"
                                                )}>
                                                    HTTP {step.status}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>

            </div>
        </div>
    );
}
