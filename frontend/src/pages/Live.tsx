import { useState, useRef, useEffect } from "react";
import { Activity, Radio, StopCircle, AlertTriangle, Shield, Zap } from "lucide-react";
import { cn } from "../utils/cn";

interface LiveEvent {
  timestamp: string;
  remote_ip: string;
  method: string;
  url: string;
  status: number;
  severity: string;
  risk_score: number;
  is_alert: boolean;
}

type TailState = "idle" | "connecting" | "live" | "error";

const BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
const MAX_FEED_ROWS = 100;

export function Live() {
  const [tailState, setTailState] = useState<TailState>("idle");
  const [logPath, setLogPath] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [stats, setStats] = useState({ total: 0, alerts: 0, perMin: 0 });
  const esRef = useRef<EventSource | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);
  const startTimeRef = useRef<number>(0);

  // Auto-scroll feed
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [events]);

  const startTail = () => {
    if (!logPath.trim()) {
      setErrorMsg("Please enter a log file path.");
      return;
    }
    setErrorMsg("");
    setTailState("connecting");
    setEvents([]);
    setStats({ total: 0, alerts: 0, perMin: 0 });
    startTimeRef.current = Date.now();

    const url = `${BASE}/api/v1/live/stream?log_path=${encodeURIComponent(logPath.trim())}`;
    const es = new EventSource(url);
    esRef.current = es;

    es.onopen = () => setTailState("live");

    es.onmessage = (e) => {
      try {
        const event: LiveEvent = JSON.parse(e.data);
        setEvents((prev) => {
          const updated = [...prev, event];
          return updated.length > MAX_FEED_ROWS ? updated.slice(-MAX_FEED_ROWS) : updated;
        });
        setStats((s) => {
          const elapsed = (Date.now() - startTimeRef.current) / 60000; // minutes
          const total = s.total + 1;
          const alerts = s.alerts + (event.is_alert ? 1 : 0);
          const perMin = elapsed > 0 ? Math.round(total / elapsed) : 0;
          return { total, alerts, perMin };
        });
      } catch {
        // Ignore malformed SSE payloads
      }
    };

    es.onerror = () => {
      setTailState("error");
      setErrorMsg("Connection lost. The server may have closed the stream or the path is invalid.");
      es.close();
    };
  };

  const stopTail = () => {
    esRef.current?.close();
    esRef.current = null;
    setTailState("idle");
  };

  // Cleanup on unmount
  useEffect(() => () => esRef.current?.close(), []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>
          Live Monitor
        </h1>
        <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
          Tail a running server access log and detect threats in real time.
        </p>
      </div>

      {/* Config panel */}
      <div className="soc-panel p-6 space-y-4">
        <h2 className="text-base font-bold" style={{ color: "var(--text-primary)" }}>
          Log File Configuration
        </h2>
        <div className="space-y-3">
          <div>
            <label htmlFor="log-path-input" className="text-xs block mb-1.5 font-medium" style={{ color: "var(--text-secondary)" }}>
              Absolute path to access log (e.g. <code className="font-mono text-[11px] px-1 py-0.5 rounded bg-[var(--bg-page)]" style={{ color: "var(--purple-dark)" }}>/var/log/nginx/access.log</code>)
            </label>
            <input
              id="log-path-input"
              type="text"
              value={logPath}
              onChange={(e) => setLogPath(e.target.value)}
              placeholder="e.g. /var/log/nginx/access.log"
              disabled={tailState === "live" || tailState === "connecting"}
              className="w-full rounded-xl border px-4 py-3 text-sm font-mono transition-all"
              style={{
                background: "var(--bg-card)",
                borderColor: "var(--border-default)",
                color: "var(--text-primary)",
              }}
              onFocus={(e) => e.target.style.borderColor = "var(--border-focus)"}
              onBlur={(e) => e.target.style.borderColor = "var(--border-default)"}
            />
          </div>
          {errorMsg && (
            <p className="text-sm flex items-center gap-2 font-medium" style={{ color: "var(--sev-critical)" }}>
              <AlertTriangle className="h-4 w-4 shrink-0" /> {errorMsg}
            </p>
          )}
          <div className="flex items-center gap-4">
            {tailState !== "live" ? (
              <button
                id="start-monitoring-btn"
                onClick={startTail}
                disabled={tailState === "connecting"}
                className="btn-primary flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-sm transition-all"
              >
                <Radio className="h-4 w-4" />
                {tailState === "connecting" ? "Connecting…" : "Start Monitoring"}
              </button>
            ) : (
              <button
                id="stop-monitoring-btn"
                onClick={stopTail}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-sm transition-all text-white bg-red-600 hover:bg-red-700 shadow-md shadow-red-600/10 hover:shadow-red-600/30"
              >
                <StopCircle className="h-4 w-4" />
                Stop
              </button>
            )}
            <div className="flex items-center gap-2 text-sm font-medium" style={{ color: "var(--text-secondary)" }}>
              <span
                className={cn(
                  "inline-block h-3 w-3 rounded-full",
                  tailState === "live" ? "bg-green-500 animate-pulse" :
                  tailState === "connecting" ? "bg-yellow-500 animate-pulse" :
                  tailState === "error" ? "bg-red-500 animate-pulse" : "bg-gray-300"
                )}
                style={{
                  boxShadow: tailState === "live" ? "0 0 8px #22C55E" :
                             tailState === "connecting" ? "0 0 8px #EAB308" :
                             tailState === "error" ? "0 0 8px #EF4444" : "none"
                }}
              />
              {tailState === "live" ? "Live" :
               tailState === "connecting" ? "Connecting" :
               tailState === "error" ? "Connection Error" : "Idle"}
            </div>
          </div>
        </div>
      </div>

      {/* Live KPI counters */}
      {(tailState === "live" || tailState === "error" || stats.total > 0) && (
        <div className="grid gap-4 grid-cols-3">
          <div className="soc-panel p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Events Seen</span>
              <Activity className="h-4 w-4" style={{ color: "var(--purple-dark)" }} />
            </div>
            <div className="text-3xl font-extrabold mt-3" style={{ color: "var(--text-primary)" }}>{stats.total.toLocaleString()}</div>
          </div>
          <div className="soc-panel p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Alerts</span>
              <Shield className="h-4 w-4" style={{ color: stats.alerts > 0 ? "var(--sev-high)" : "var(--text-muted)" }} />
            </div>
            <div className={cn("text-3xl font-extrabold mt-3", stats.alerts > 0 ? "text-red-500" : "text-gray-500")} style={stats.alerts > 0 ? { color: "var(--sev-critical)" } : { color: "var(--text-primary)" }}>
              {stats.alerts}
            </div>
          </div>
          <div className="soc-panel p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>Events / min</span>
              <Zap className="h-4 w-4" style={{ color: "var(--purple-mid)" }} />
            </div>
            <div className="text-3xl font-extrabold mt-3" style={{ color: "var(--text-primary)" }}>{stats.perMin}</div>
          </div>
        </div>
      )}

      {/* Live event feed */}
      {events.length > 0 && (
        <div className="soc-panel overflow-hidden">
          <div className="px-6 py-4 border-b flex items-center justify-between" style={{ borderColor: "var(--border-default)" }}>
            <h3 className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>Live Event Feed</h3>
            <span className="text-xs px-2.5 py-1 rounded-full font-medium" style={{ background: "var(--purple-light)", color: "var(--purple-dark)" }}>
              Last {events.length} events
            </span>
          </div>
          <div className="p-0">
            <div
              ref={feedRef}
              className="h-[400px] overflow-y-auto text-xs font-mono"
            >
              <table className="data-table">
                <thead className="sticky top-0 bg-white z-10">
                  <tr>
                    <th>Time</th>
                    <th>IP</th>
                    <th>Method</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev, i) => (
                    <tr
                      key={i}
                      className={cn(
                        "transition-colors",
                        ev.is_alert ? "bg-red-50/70 hover:bg-red-50" : "hover:bg-[var(--bg-page)]"
                      )}
                    >
                      <td style={{ color: "var(--text-muted)" }} className="whitespace-nowrap font-mono-soc text-[11px]">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="whitespace-nowrap font-semibold" style={{ color: "var(--purple-dark)" }}>
                        {ev.remote_ip}
                      </td>
                      <td>
                        <span className={cn(
                          "font-bold px-1.5 py-0.5 rounded text-[10px]",
                          ev.method === "POST" ? "bg-blue-100 text-blue-800" :
                          ev.method === "GET" ? "bg-green-100 text-green-800" :
                          "bg-yellow-100 text-yellow-800"
                        )}>{ev.method}</span>
                      </td>
                      <td className="max-w-[280px] truncate font-mono-soc" title={ev.url} style={{ color: "var(--text-secondary)" }}>
                        {ev.url}
                      </td>
                      <td className="font-semibold">
                        <span className={cn(
                          ev.status >= 500 ? "text-red-600" :
                          ev.status >= 400 ? "text-orange-600" :
                          "text-gray-600"
                        )}>
                          {ev.status}
                        </span>
                      </td>
                      <td>
                        {ev.severity !== "NONE" ? (
                          <span className={cn(
                            "badge",
                            ev.severity === "CRITICAL" ? "badge-critical" :
                            ev.severity === "HIGH" ? "badge-high" :
                            ev.severity === "MEDIUM" ? "badge-medium" : "badge-low"
                          )}>
                            {ev.severity}
                          </span>
                        ) : (
                          <span style={{ color: "var(--text-muted)" }}>—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Idle empty state */}
      {tailState === "idle" && events.length === 0 && (
        <div className="soc-panel py-16 flex flex-col items-center justify-center text-center space-y-3">
          <div className="w-12 h-12 rounded-full flex items-center justify-center bg-gray-100 text-gray-400">
            <Radio className="h-6 w-6" />
          </div>
          <div>
            <p className="font-bold text-base" style={{ color: "var(--text-primary)" }}>No active session</p>
            <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>Enter your log path above and click start to stream live access logs.</p>
          </div>
        </div>
      )}
    </div>
  );
}
