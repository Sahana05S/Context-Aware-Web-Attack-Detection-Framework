import React, { useEffect, useState } from "react";
import { api } from "../api/endpoints";
import { AlertSummary } from "../api/types";
import { Link } from "react-router-dom";
import { RefreshCw, AlertTriangle, Brain, ShieldOff } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertDetailPanel } from "../components/AlertDetailPanel";

/* ─── Rule explanation map ─────────────────────────────────────────────── */
const ruleExplanations: Record<string, string> = {
    suspicious_user_agent:
        "A suspicious User-Agent string was detected. This is often associated with automated vulnerability scanners, bots, or known reconnaissance tools actively mapping out the application.",
    sqli_pattern_detected:
        "The request contains patterns commonly associated with SQL Injection (SQLi) attacks. The payload is attempting to manipulate backend database queries, potentially leading to unauthorized data access or modification.",
    xss_pattern_detected:
        "Cross-Site Scripting (XSS) payload signatures were found in the request. The attacker is attempting to inject malicious scripts into the application to trick other users' browsers into executing it.",
    path_traversal_pattern_detected:
        "Directory Traversal markers (e.g., '../') were identified. The traffic indicates an attempt to navigate outside the intended web root directory to access sensitive system files.",
    command_injection_pattern_detected:
        "Operating system command injections were detected. The requester is attempting to execute arbitrary system commands via the web application interface.",
    ssrf_pattern_detected:
        "Server-Side Request Forgery (SSRF) patterns were detected. The attacker is trying to coerce the server into making HTTP requests to arbitrary, internal, or external domains.",
    hpp_pattern_detected:
        "HTTP Parameter Pollution (HPP) was detected. The request contains multiple parameters with the same name, confusing the backend processor into evaluating malicious overwrites.",
    typosquatting_admin_detected:
        "An attempt to access sensitive, predictable administrative endpoints or typosquatted common directories was detected.",
};

/* ─── formatContextReason (logic unchanged, restyled output) ────────────── */
function formatContextReason(rawReason: string) {
    if (rawReason.startsWith("Rule: ")) {
        const match = rawReason.match(/Rule:\s*([a-zA-Z0-9_]+)\s*\((.*?)\)/);
        if (match) {
            const ruleName = match[1];
            const explanation =
                ruleExplanations[ruleName] ||
                "A heuristic rule was triggered indicating malicious behavior.";
            return (
                <div
                    className="mb-3 rounded-lg px-4 py-3"
                    style={{
                        background: "var(--bg-page)",
                        border: "1px solid var(--border-default)",
                    }}
                >
                    <div
                        className="text-xs font-bold tracking-wide uppercase mb-1"
                        style={{ color: "#493D9E" }}
                    >
                        Heuristic Rule Triggered
                        <span
                            className="ml-2 font-mono normal-case"
                            style={{ color: "#B2A5FF" }}
                        >
                            {ruleName}
                        </span>
                    </div>
                    <div className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                        {explanation}
                    </div>
                </div>
            );
        }
    }

    if (rawReason.startsWith("ML: ")) {
        const match = rawReason.match(/ML:\s*([\d.]+)\s*([A-Za-z]+)/);
        if (match) {
            const score = match[1];
            const confidence = match[2];
            return (
                <div
                    className="mb-3 rounded-lg px-4 py-3"
                    style={{
                        background: "var(--bg-page)",
                        border: "1px solid var(--border-default)",
                    }}
                >
                    <div
                        className="text-xs font-bold tracking-wide uppercase mb-1"
                        style={{ color: "#493D9E" }}
                    >
                        AI Prediction Score
                        <span className="ml-2 font-mono normal-case" style={{ color: "#B2A5FF" }}>
                            {score}
                        </span>
                    </div>
                    <div className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                        The neural classification model evaluated this request payload and
                        assigned a threat probability score of{" "}
                        <span className="font-mono font-semibold" style={{ color: "#493D9E" }}>
                            {score}
                        </span>{" "}
                        with <span className="font-bold">{confidence}</span> confidence.
                    </div>
                </div>
            );
        }
    }

    return (
        <li className="mb-1 list-disc ml-4 text-xs" style={{ color: "var(--text-secondary)" }}>
            {rawReason}
        </li>
    );
}

/* ─── Severity badge helper ─────────────────────────────────────────────── */
function SeverityBadgeInline({ severity }: { severity: string }) {
    const s = severity?.toLowerCase();
    if (s === "critical") return <span className="badge badge-critical">{severity}</span>;
    if (s === "high") return <span className="badge badge-high">{severity}</span>;
    if (s === "medium") return <span className="badge badge-medium">{severity}</span>;
    return <span className="badge badge-low">{severity}</span>;
}

/* ─── Risk score color helper ───────────────────────────────────────────── */
function riskColor(score: number) {
    if (score >= 70) return "#e13d3d";
    if (score >= 40) return "#f2a93b";
    return "#22c55e";
}

/* ─── Component ─────────────────────────────────────────────────────────── */
export function Alerts() {
    const [alerts, setAlerts] = useState<AlertSummary[]>([]);
    const [totalAlerts, setTotalAlerts] = useState(0);
    const [page, setPage] = useState(1);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [limit, setLimit] = useState(200);
    const [sinceMinutes, setSinceMinutes] = useState(1440);
    const [expandedAlert, setExpandedAlert] = useState<number | null>(null);

    const loadData = async () => {
        setLoading(true);
        setError(null);
        try {
            const offset = (page - 1) * limit;
            const data = await api.alerts({ limit, offset, since_minutes: sinceMinutes });
            setAlerts(data.alerts);
            setTotalAlerts(data.total);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to load alerts");
        } finally {
            setLoading(false);
        }
    };

    // Reset to page 1 when filters change
    useEffect(() => {
        setPage(1);
    }, [limit, sinceMinutes]);

    useEffect(() => {
        loadData();
    }, [page, limit, sinceMinutes]);

    return (
        <div className="space-y-6">

            {/* ── Page header ── */}
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1
                        className="text-2xl font-bold tracking-tight"
                        style={{ color: "var(--text-primary)" }}
                    >
                        Alerts
                    </h1>
                    <p className="text-sm mt-0.5" style={{ color: "var(--text-muted)" }}>
                        Real-time threat detections
                    </p>
                </div>

                {/* ── Filter row ── */}
                <div className="flex items-center gap-2 flex-wrap">
                    <select
                        className="input-field text-xs py-1.5 pr-8 pl-3 h-9"
                        value={sinceMinutes}
                        onChange={(e) => setSinceMinutes(Number(e.target.value))}
                    >
                        <option value="60">Last 1 Hour</option>
                        <option value="1440">Last 24 Hours</option>
                        <option value="10080">Last 7 Days</option>
                    </select>

                    <select
                        className="input-field text-xs py-1.5 pr-8 pl-3 h-9"
                        value={limit}
                        onChange={(e) => setLimit(Number(e.target.value))}
                    >
                        <option value="50">Show 50</option>
                        <option value="100">Show 100</option>
                        <option value="200">Show 200</option>
                    </select>

                    <button
                        onClick={loadData}
                        disabled={loading}
                        className="btn-primary flex items-center gap-1.5 text-xs h-9 px-4 disabled:opacity-60"
                    >
                        <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
                        Refresh
                    </button>
                </div>
            </div>

            {/* ── Alert count badge ── */}
            {!loading && !error && (
                <div className="flex items-center justify-between">
                    <span
                        className="badge"
                        style={{
                            background: "#DAD2FF",
                            color: "#493D9E",
                            fontWeight: 700,
                            fontSize: "0.7rem",
                            letterSpacing: "0.05em",
                            textTransform: "uppercase",
                        }}
                    >
                        {totalAlerts} ALERTS FOUND{" "}
                        <span style={{ fontWeight: 400, marginLeft: "4px", color: "#7462C2" }}>
                            (SHOWING {(page - 1) * limit + 1}—{Math.min(page * limit, totalAlerts)})
                        </span>
                    </span>

                    {/* Pagination Controls - Top */}
                    <div className="flex items-center gap-2">
                        <button
                            disabled={page === 1}
                            onClick={() => setPage(p => Math.max(1, p - 1))}
                            className="btn-secondary text-xs h-8 px-3 disabled:opacity-50"
                        >
                            Prev
                        </button>
                        <span className="text-xs text-gray-500 font-medium px-2">Page {page} of {Math.max(1, Math.ceil(totalAlerts / limit))}</span>
                        <button
                            disabled={page * limit >= totalAlerts}
                            onClick={() => setPage(p => p + 1)}
                            className="btn-secondary text-xs h-8 px-3 disabled:opacity-50"
                        >
                            Next
                        </button>
                    </div>
                </div>
            )}

            {/* ── Table panel ── */}
            <div className="soc-panel overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="data-table w-full">
                        <thead>
                            <tr style={{ borderBottom: "1px solid var(--border-default)" }}>
                                {["Time", "Severity", "IP Address", "Risk Score", "Title", "Status"].map(
                                    (h) => (
                                        <th
                                            key={h}
                                            className="text-left px-5 py-3 text-[10px] font-semibold tracking-widest uppercase"
                                            style={{ color: "var(--text-muted)" }}
                                        >
                                            {h}
                                        </th>
                                    )
                                )}
                            </tr>
                        </thead>

                        <tbody>
                            {/* Loading state */}
                            {loading ? (
                                <tr>
                                    <td colSpan={6} className="px-5 py-16 text-center">
                                        <div className="flex flex-col items-center gap-3">
                                            <RefreshCw
                                                className="h-6 w-6 animate-spin"
                                                style={{ color: "#B2A5FF" }}
                                            />
                                            <span className="text-sm" style={{ color: "var(--text-muted)" }}>
                                                Loading alerts...
                                            </span>
                                        </div>
                                    </td>
                                </tr>
                            ) : error ? (
                                /* Error state */
                                <tr>
                                    <td colSpan={6} className="px-5 py-16 text-center">
                                        <div className="flex flex-col items-center gap-3">
                                            <AlertTriangle className="h-6 w-6" style={{ color: "#e13d3d" }} />
                                            <span className="text-sm font-medium" style={{ color: "#e13d3d" }}>
                                                {error}
                                            </span>
                                        </div>
                                    </td>
                                </tr>
                            ) : alerts.length === 0 ? (
                                /* Empty state */
                                <tr>
                                    <td colSpan={6} className="px-5 py-16 text-center">
                                        <div className="flex flex-col items-center gap-3">
                                            <ShieldOff className="h-6 w-6" style={{ color: "var(--text-muted)" }} />
                                            <span className="text-sm" style={{ color: "var(--text-muted)" }}>
                                                No alerts found for this period.
                                            </span>
                                        </div>
                                    </td>
                                </tr>
                            ) : (
                                /* Data rows */
                                alerts.map((alert) => (
                                    <React.Fragment key={alert.id}>
                                        {/* ── Main row ── */}
                                        <tr
                                            onClick={() =>
                                                setExpandedAlert(
                                                    expandedAlert === alert.id ? null : alert.id
                                                )
                                            }
                                            className="cursor-pointer transition-colors"
                                            style={{
                                                borderBottom:
                                                    expandedAlert === alert.id
                                                        ? "none"
                                                        : "1px solid var(--border-default)",
                                            }}
                                            onMouseEnter={(e) =>
                                                (e.currentTarget.style.background = "var(--bg-page)")
                                            }
                                            onMouseLeave={(e) =>
                                                (e.currentTarget.style.background = "transparent")
                                            }
                                        >
                                            {/* Time */}
                                            <td
                                                className="px-5 py-3 font-mono-soc text-[11px] whitespace-nowrap"
                                                style={{ color: "var(--text-muted)" }}
                                            >
                                                {new Date(alert.created_at).toLocaleString()}
                                            </td>

                                            {/* Severity */}
                                            <td className="px-5 py-3">
                                                <SeverityBadgeInline severity={alert.severity} />
                                            </td>

                                            {/* IP Address */}
                                            <td className="px-5 py-3">
                                                <Link
                                                    to={`/ips/${alert.remote_ip}`}
                                                    onClick={(e) => e.stopPropagation()}
                                                    className="font-mono-soc text-xs font-semibold transition-colors hover:underline"
                                                    style={{ color: "#493D9E" }}
                                                >
                                                    {alert.remote_ip}
                                                </Link>
                                            </td>

                                            {/* Risk Score */}
                                            <td className="px-5 py-3">
                                                <span
                                                    className="text-sm font-bold block"
                                                    style={{ color: riskColor(alert.risk_score) }}
                                                >
                                                    {alert.risk_score}
                                                </span>
                                                <div
                                                    className="risk-bar-track mt-1"
                                                    style={{ width: "60px" }}
                                                >
                                                    <div
                                                        className="risk-bar-fill"
                                                        style={{
                                                            width: `${Math.min(alert.risk_score, 100)}%`,
                                                            background: riskColor(alert.risk_score),
                                                        }}
                                                    />
                                                </div>
                                            </td>

                                            {/* Title */}
                                            <td
                                                className="px-5 py-3 max-w-[220px] truncate text-xs"
                                                title={alert.title}
                                                style={{ color: "var(--text-secondary)" }}
                                            >
                                                {alert.title}
                                            </td>

                                            {/* Status */}
                                            <td className="px-5 py-3">
                                                <span
                                                    className="text-[10px] font-bold tracking-widest uppercase"
                                                    style={{
                                                        color:
                                                            alert.status === "open"
                                                                ? "#f2c14a"
                                                                : "#22c55e",
                                                    }}
                                                >
                                                    {alert.status}
                                                </span>
                                            </td>
                                        </tr>

                                        {/* ── Expanded reasoning row ── */}
                                        <AnimatePresence>
                                            {expandedAlert === alert.id && (
                                                <motion.tr
                                                    initial={{ opacity: 0 }}
                                                    animate={{ opacity: 1 }}
                                                    exit={{ opacity: 0 }}
                                                    transition={{ duration: 0.18, ease: "easeInOut" }}
                                                    style={{
                                                        borderBottom: "1px solid var(--border-default)",
                                                        display: "table-row",
                                                        background: "var(--bg-page)",
                                                    }}
                                                >
                                                    <td colSpan={6} className="px-5 py-4">
                                                        <motion.div
                                                            initial={{ opacity: 0, y: -8 }}
                                                            animate={{ opacity: 1, y: 0 }}
                                                            exit={{ opacity: 0, y: -8 }}
                                                            transition={{ duration: 0.18, delay: 0.05 }}
                                                        >
                                                            <AlertDetailPanel alert={alert} />
                                                        </motion.div>
                                                    </td>
                                                </motion.tr>
                                            )}
                                        </AnimatePresence>
                                    </React.Fragment>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>

                {/* Pagination Controls - Bottom */}
                {totalAlerts > limit && (
                    <div className="p-4 border-t border-gray-100 flex items-center justify-between bg-gray-50/50">
                        <div className="text-xs text-gray-500">
                            Showing {(page - 1) * limit + 1} to {Math.min(page * limit, totalAlerts)} of {totalAlerts} entries
                        </div>
                        <div className="flex items-center gap-2">
                            <button
                                disabled={page === 1}
                                onClick={() => setPage(p => Math.max(1, p - 1))}
                                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                Previous
                            </button>
                            <button
                                disabled={page * limit >= totalAlerts}
                                onClick={() => setPage(p => p + 1)}
                                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                Next
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
