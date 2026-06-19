import { useEffect, useState, useRef } from "react";
import { api } from "../api/endpoints";
import { OverviewStats, AlertSummary } from "../api/types";
import { StatsCard } from "../components/layout/StatsCard";
import { RiskTrendChart } from "../components/charts/RiskTrendChart";
import { AttackTypeChart } from "../components/charts/AttackTypeChart";
import { SeverityPieChart } from "../components/charts/SeverityPieChart";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { AlertTriangle, Shield, Activity, Users, RefreshCw, Clock, Brain } from "lucide-react";
import { Link } from "react-router-dom";
import { motion, Variants } from "framer-motion";

export function Dashboard() {
    const [stats, setStats] = useState<OverviewStats | null>(null);
    const [recentAlerts, setRecentAlerts] = useState<AlertSummary[]>([]);
    const [aiSummary, setAiSummary] = useState<string>("Loading AI summary...");
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [retrying, setRetrying] = useState(false);
    const [retryCountdown, setRetryCountdown] = useState(0);
    const [sinceMinutes, setSinceMinutes] = useState(1440); // 24h
    const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
    const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    const loadData = async (isRetry = false) => {
        if (!isRetry) setLoading(true);
        setError(null);
        setRetrying(false);
        if (retryTimerRef.current) clearTimeout(retryTimerRef.current);
        try {
            const [statsData, alertsData, aiSummaryData] = await Promise.all([
                api.overview(sinceMinutes),
                api.alerts({ limit: 8, since_minutes: sinceMinutes }),
                api.aiSummary(sinceMinutes)
            ]);
            setStats(statsData);
            setRecentAlerts(alertsData.alerts);
            setAiSummary(aiSummaryData.summary);
            setLastRefresh(new Date());
        } catch (err) {
            const msg = err instanceof Error ? err.message : "Failed to load dashboard data";
            setError(msg);
            // Auto-retry after 15s (handles Render cold-start)
            setRetrying(true);
            setRetryCountdown(15);
            const countdown = setInterval(() => {
                setRetryCountdown(prev => {
                    if (prev <= 1) { clearInterval(countdown); return 0; }
                    return prev - 1;
                });
            }, 1000);
            retryTimerRef.current = setTimeout(() => {
                clearInterval(countdown);
                setRetrying(false);
                loadData(true);
            }, 15000);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadData();
        return () => { if (retryTimerRef.current) clearTimeout(retryTimerRef.current); };
    }, [sinceMinutes]);

    if (loading && !stats) return (
        <div className="flex items-center justify-center h-64">
            <div className="flex items-center gap-3" style={{ color: 'var(--text-muted)' }}>
                <RefreshCw className="h-4 w-4 animate-spin" style={{ color: 'var(--purple-dark)' }} />
                <span className="text-sm font-medium">Loading dashboard…</span>
            </div>
        </div>
    );

    if (error) return (
        <div className="flex flex-col items-center justify-center h-64 gap-4" style={{ textAlign: 'center' }}>
            <div style={{
                width: 64, height: 64, borderRadius: '50%',
                background: 'linear-gradient(135deg, #FFF2AF 0%, #FFD700 100%)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                boxShadow: '0 4px 20px rgba(251,191,36,0.3)'
            }}>
                <AlertTriangle className="h-7 w-7" style={{ color: '#B45309' }} />
            </div>
            <div>
                <p className="text-base font-semibold" style={{ color: '#1A1433', marginBottom: 4 }}>
                    {retrying ? '⚡ Backend is waking up…' : 'Unable to reach backend'}
                </p>
                <p className="text-sm" style={{ color: 'var(--text-muted)', maxWidth: 360 }}>
                    {retrying
                        ? `The server on Render's free tier needs ~30s to start. Auto-retrying in ${retryCountdown}s…`
                        : 'The API server did not respond. It may be starting up or temporarily unavailable.'}
                </p>
            </div>
            {retrying ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--purple-mid)', fontSize: '0.85rem' }}>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    <span>Retrying in {retryCountdown}s…</span>
                </div>
            ) : null}
            <button onClick={() => loadData(false)} className="btn-primary text-sm" style={{ marginTop: 4 }}>
                Retry Now
            </button>
        </div>
    );

    if (!stats) return null;

    const totalAlerts = Object.values(stats.alert_counts).reduce((a, b) => a + b, 0);
    const criticalCount = stats.alert_counts["CRITICAL"] || 0;
    const avgRisk = Math.round(
        stats.risk_trend.reduce((acc, curr) => acc + curr.avg_risk, 0) / (stats.risk_trend.length || 1)
    );

    const containerVariants: Variants = {
        hidden: { opacity: 0 },
        visible: {
            opacity: 1,
            transition: { staggerChildren: 0.1 }
        }
    };

    const itemVariants: Variants = {
        hidden: { y: 20, opacity: 0 },
        visible: { y: 0, opacity: 1, transition: { type: "spring", stiffness: 100 } }
    };

    return (
        <div className="space-y-6" style={{ color: 'var(--text-primary)' }}>

            {/* ── Page Header ────────────────────────────────── */}
            <div className="flex items-center justify-between">
                <div>
                    <h1
                        className="text-2xl font-bold tracking-tight"
                        style={{ color: '#1A1433' }}
                    >
                        SOC Overview
                    </h1>
                    <div className="flex items-center gap-1.5 mt-1">
                        <Clock className="h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            Last refresh: {lastRefresh.toLocaleTimeString()}
                        </span>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    {/* Time-range selector */}
                    <select
                        className="text-xs px-3 py-2 rounded-lg font-medium outline-none cursor-pointer"
                        style={{
                            background: 'var(--bg-page)',
                            border: '1.5px solid var(--border-default)',
                            color: 'var(--text-primary)',
                        }}
                        value={sinceMinutes}
                        onChange={(e) => setSinceMinutes(Number(e.target.value))}
                    >
                        <option value="60">Last 1 Hour</option>
                        <option value="360">Last 6 Hours</option>
                        <option value="1440">Last 24 Hours</option>
                        <option value="10080">Last 7 Days</option>
                    </select>

                    {/* Refresh button */}
                    <button
                        onClick={() => loadData(false)}
                        disabled={loading}
                        className="btn-outline flex items-center gap-1.5 text-xs"
                        style={{ opacity: loading ? 0.65 : 1, padding: '7px 14px' }}
                    >
                        <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
                        Refresh
                    </button>
                </div>
            </div>

            {/* ── KPI Cards ──────────────────────────────────── */}
            <motion.div
                variants={containerVariants}
                initial="hidden"
                animate="visible"
                className="grid gap-4 grid-cols-2 lg:grid-cols-4"
            >
                <motion.div variants={itemVariants}>
                    <StatsCard
                        title="Total Alerts"
                        value={totalAlerts}
                        icon={Shield}
                        description="In selected period"
                        accentColor="#493D9E"
                    />
                </motion.div>
                <motion.div variants={itemVariants}>
                    <StatsCard
                        title="Critical Threats"
                        value={criticalCount}
                        icon={AlertTriangle}
                        description="Requires immediate attention"
                        accentColor={criticalCount > 0 ? "#DC2626" : "#16A34A"}
                    />
                </motion.div>
                <motion.div variants={itemVariants}>
                    <StatsCard
                        title="Top Attacking IP"
                        value={stats.top_ips[0]?.remote_ip || "—"}
                        icon={Users}
                        description={`${stats.top_ips[0]?.event_count || 0} events`}
                        accentColor="#B2A5FF"
                    />
                </motion.div>
                <motion.div variants={itemVariants}>
                    <StatsCard
                        title="Avg Risk Score"
                        value={avgRisk}
                        icon={Activity}
                        description="Across all traffic"
                        accentColor={avgRisk >= 60 ? "#DC2626" : avgRisk >= 40 ? "#CA8A04" : "#16A34A"}
                    />
                </motion.div>
            </motion.div>

            {/* ── AI Insight Panel ───────────────────────────── */}
            <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.35, duration: 0.4 }}
            >
                <div
                    className="soc-panel p-5 flex items-start gap-4"
                    style={{
                        background: 'linear-gradient(135deg, #EDE9FF 0%, #F5F3FF 100%)',
                        borderColor: 'var(--purple-light)',
                    }}
                >
                    {/* Brain icon bubble */}
                    <div
                        className="flex-shrink-0 flex items-center justify-center rounded-xl"
                        style={{
                            width: 44,
                            height: 44,
                            background: 'var(--purple-dark)',
                            boxShadow: '0 4px 12px rgba(73,61,158,0.25)',
                        }}
                    >
                        <Brain className="h-5 w-5" style={{ color: '#fff' }} />
                    </div>

                    {/* Insight content */}
                    <div className="flex-1 min-w-0">
                        <div className="ai-insight-label mb-1">
                            🤖 AI Threat Summary
                        </div>
                        <p className="ai-insight-text">
                            {aiSummary}
                        </p>
                    </div>

                    {/* Live badge */}
                    <div className="flex-shrink-0 flex items-center gap-1.5 mt-0.5">
                        <span className="status-dot online" />
                        <span
                            className="text-[10px] font-bold uppercase tracking-widest"
                            style={{ color: '#16A34A' }}
                        >
                            Live
                        </span>
                    </div>
                </div>
            </motion.div>

            {/* ── Charts Row 1: Risk Trend + Severity Pie ────── */}
            <motion.div
                variants={containerVariants}
                initial="hidden"
                animate="visible"
                className="grid gap-4 lg:grid-cols-7"
            >
                <motion.div variants={itemVariants} className="lg:col-span-4">
                    <RiskTrendChart data={stats.risk_trend} />
                </motion.div>
                <motion.div variants={itemVariants} className="lg:col-span-3">
                    <SeverityPieChart data={stats.alert_counts} />
                </motion.div>
            </motion.div>

            {/* ── Charts Row 2: Attack Types + Recent Alerts ─── */}
            <motion.div
                variants={containerVariants}
                initial="hidden"
                animate="visible"
                className="grid gap-4 lg:grid-cols-7"
            >
                {/* Attack Type Chart */}
                <motion.div variants={itemVariants} className="lg:col-span-3">
                    <AttackTypeChart data={stats.attack_types} />
                </motion.div>

                {/* Recent Alerts Table */}
                <motion.div variants={itemVariants} className="lg:col-span-4">
                    <div className="soc-panel p-5">

                        {/* Section header */}
                        <div className="flex items-center justify-between mb-4">
                            <h3
                                className="text-[11px] font-bold tracking-widest uppercase"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                Recent Alerts
                            </h3>
                            <Link
                                to="/alerts"
                                className="text-[11px] font-semibold transition-colors hover:underline"
                                style={{ color: 'var(--purple-dark)' }}
                            >
                                View all →
                            </Link>
                        </div>

                        <div className="overflow-x-auto">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>IP Address</th>
                                        <th>Title</th>
                                        <th>Time</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {recentAlerts.length === 0 ? (
                                        <tr>
                                            <td
                                                colSpan={4}
                                                className="py-10 text-center text-sm"
                                                style={{ color: 'var(--text-muted)' }}
                                            >
                                                No recent alerts found.
                                            </td>
                                        </tr>
                                    ) : (
                                        recentAlerts.map((alert) => (
                                            <tr key={alert.id}>
                                                <td>
                                                    <SeverityBadge severity={alert.severity} />
                                                </td>
                                                <td>
                                                    <Link
                                                        to={`/ips/${alert.remote_ip}`}
                                                        className="font-mono-soc font-medium transition-colors hover:underline"
                                                        style={{ color: 'var(--purple-dark)' }}
                                                    >
                                                        {alert.remote_ip}
                                                    </Link>
                                                </td>
                                                <td
                                                    className="max-w-[180px] truncate"
                                                    title={alert.title}
                                                    style={{ color: 'var(--text-secondary)' }}
                                                >
                                                    {alert.title}
                                                </td>
                                                <td>
                                                    <span
                                                        className="font-mono-soc text-[11px]"
                                                        style={{ color: 'var(--text-muted)' }}
                                                    >
                                                        {new Date(alert.created_at).toLocaleTimeString()}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </motion.div>
            </motion.div>
        </div>
    );
}
