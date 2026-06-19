import { useState, useRef, DragEvent, ChangeEvent } from "react";
import { Link } from "react-router-dom";
import {
  UploadCloud, FileText, CheckCircle, AlertTriangle,
  ArrowRight, X, Trash2, RefreshCw
} from "lucide-react";
import { cn } from "../utils/cn";

interface UploadResult {
  filename: string;
  format_detected: string;
  total_lines: number;
  processed: number;
  skipped: number;
  errors: number;
  alerts_triggered: number;
}

type UploadState = "idle" | "uploading" | "done" | "error";
type ClearState = "idle" | "confirming" | "clearing" | "cleared" | "error";

const BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export function Upload() {
  const [state, setState] = useState<UploadState>("idle");
  const [result, setResult] = useState<UploadResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string>("");
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState<string>("");
  const [progress, setProgress] = useState(0);
  const [clearState, setClearState] = useState<ClearState>("idle");
  const fileRef = useRef<HTMLInputElement>(null);

  const reset = () => {
    setState("idle");
    setResult(null);
    setErrorMsg("");
    setFileName("");
    setProgress(0);
    if (fileRef.current) fileRef.current.value = "";
  };

  const uploadFile = async (file: File) => {
    setFileName(file.name);
    setState("uploading");
    setProgress(10);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const ticker = setInterval(() => setProgress((p) => Math.min(p + 8, 85)), 600);
      const res = await fetch(`${BASE}/api/v1/ingest/upload`, {
        method: "POST",
        body: formData,
      });
      clearInterval(ticker);
      setProgress(100);

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || `Server error: ${res.status}`);
      }

      const data: UploadResult = await res.json();
      setResult(data);
      setState("done");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Upload failed");
      setState("error");
    }
  };

  const clearLogs = async () => {
    setClearState("clearing");
    try {
      const res = await fetch(`${BASE}/api/v1/ingest/clear`, { method: "DELETE" });
      if (!res.ok) throw new Error(`Server error ${res.status}`);
      setClearState("cleared");
      reset();
      setTimeout(() => setClearState("idle"), 3000);
    } catch {
      setClearState("error");
      setTimeout(() => setClearState("idle"), 3000);
    }
  };

  const handleFileInput = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) uploadFile(file);
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) uploadFile(file);
  };

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight" style={{ color: "var(--text-primary)" }}>
            Upload Logs
          </h1>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
            Upload an access log file to analyze and populate the dashboard.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {state !== "idle" && (
            <button
              onClick={reset}
              title="Start over"
              className="p-2 rounded-xl border transition-colors hover:bg-gray-50"
              style={{ borderColor: "var(--border-default)" }}
            >
              <X className="h-4 w-4" style={{ color: "var(--text-secondary)" }} />
            </button>
          )}

          {/* ── Clear Logs button ── */}
          {clearState === "idle" && (
            <button
              id="clear-logs-btn"
              className="flex items-center gap-2 px-3 py-1.5 rounded-xl border font-semibold text-xs transition-all text-red-600 border-red-200 bg-red-50 hover:bg-red-100 hover:text-red-700"
              onClick={() => setClearState("confirming")}
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear Logs
            </button>
          )}
          {clearState === "confirming" && (
            <div className="flex items-center gap-2 bg-red-50 border border-red-200 rounded-xl px-3 py-1.5">
              <span className="text-xs font-bold text-red-800">Clear all data?</span>
              <button
                className="px-2.5 py-1 text-[11px] font-bold text-white bg-red-600 hover:bg-red-700 rounded-lg transition-all"
                onClick={clearLogs}
              >
                Yes, clear
              </button>
              <button
                className="px-2.5 py-1 text-[11px] font-semibold text-gray-700 bg-white hover:bg-gray-100 border border-gray-200 rounded-lg transition-all"
                onClick={() => setClearState("idle")}
              >
                Cancel
              </button>
            </div>
          )}
          {clearState === "clearing" && (
            <div className="flex items-center gap-2 text-xs font-medium" style={{ color: "var(--text-muted)" }}>
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              Clearing database…
            </div>
          )}
          {clearState === "cleared" && (
            <div className="flex items-center gap-2 text-xs font-bold text-green-600">
              <CheckCircle className="h-3.5 w-3.5" />
              Database cleared
            </div>
          )}
          {clearState === "error" && (
            <span className="text-xs font-bold text-red-600">Clear failed</span>
          )}
        </div>
      </div>

      {/* Format hint */}
      <div className="soc-panel p-5 space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
          Supported Log Formats
        </h3>
        <div className="grid grid-cols-2 gap-4 text-sm pt-1">
          <div className="flex items-start gap-2.5">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-blue-50 text-blue-600 mt-0.5">
              <FileText className="h-4.5 w-4.5" />
            </div>
            <div>
              <p className="font-bold text-sm" style={{ color: "var(--text-primary)" }}>Nginx / Apache Combined</p>
              <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>Standard access.log line format</p>
            </div>
          </div>
          <div className="flex items-start gap-2.5">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-amber-50 text-amber-600 mt-0.5">
              <FileText className="h-4.5 w-4.5" />
            </div>
            <div>
              <p className="font-bold text-sm" style={{ color: "var(--text-primary)" }}>CSV (Custom Schema)</p>
              <p className="text-xs mt-0.5 font-mono" style={{ color: "var(--text-muted)" }}>
                timestamp, remote_ip, method, url, status_code, user_agent
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Drop zone */}
      {state === "idle" && (
        <div
          id="upload-dropzone"
          className={cn(
            "border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all",
            dragging
              ? "border-[var(--purple-dark)] bg-[var(--purple-light)]/10"
              : "border-[var(--border-default)] hover:border-[var(--purple-mid)] hover:bg-[var(--bg-page)]/50"
          )}
          onClick={() => fileRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
        >
          <UploadCloud className="h-12 w-12 mx-auto mb-4" style={{ color: "var(--purple-dark)" }} />
          <p className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>Drop your log file here</p>
          <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>or click to browse local files — max 50 MB</p>
          <input
            ref={fileRef}
            type="file"
            accept=".log,.txt,.csv,.access"
            className="hidden"
            onChange={handleFileInput}
            id="file-input"
          />
        </div>
      )}

      {/* Uploading progress */}
      {state === "uploading" && (
        <div className="soc-panel p-6 space-y-4">
          <div className="flex items-center gap-3">
            <FileText className="h-5 w-5" style={{ color: "var(--purple-dark)" }} />
            <span className="text-sm font-bold truncate max-w-sm" style={{ color: "var(--text-primary)" }}>{fileName}</span>
          </div>
          <div className="space-y-2">
            <div className="h-2.5 rounded-full overflow-hidden" style={{ background: "var(--bg-page)" }}>
              <div
                className="h-full transition-all duration-500 rounded-full"
                style={{ width: `${progress}%`, background: "var(--purple-dark)" }}
              />
            </div>
            <p className="text-xs font-semibold" style={{ color: "var(--text-muted)" }}>
              {progress < 90 ? "Uploading and processing events…" : "Finalizing security indexing…"}
            </p>
          </div>
        </div>
      )}

      {/* Error */}
      {state === "error" && (
        <div className="soc-panel p-6 border-red-200 bg-red-50/20 space-y-3">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" style={{ color: "var(--sev-critical)" }} />
            <div className="space-y-2 flex-1">
              <p className="font-bold text-red-800">Upload failed</p>
              <p className="text-sm text-red-700">{errorMsg}</p>
              <button
                onClick={reset}
                className="px-4 py-2 text-xs font-semibold rounded-xl border border-red-200 text-red-800 bg-white hover:bg-red-50 transition-all mt-1"
              >
                Try again
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Success summary */}
      {state === "done" && result && (
        <div className="soc-panel p-6 space-y-5">
          <div className="flex items-start gap-3">
            <div className="p-1.5 rounded-lg bg-green-100 text-green-700 shrink-0">
              <CheckCircle className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-extrabold text-base" style={{ color: "var(--text-primary)" }}>Log Processing Complete</h3>
              <p className="text-xs mt-0.5 font-mono" style={{ color: "var(--text-muted)" }}>
                {result.filename} · Format: {result.format_detected.toUpperCase()}
              </p>
            </div>
          </div>
          
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              { label: "Total Lines", value: result.total_lines, class: "" },
              { label: "Processed", value: result.processed, class: "text-green-600" },
              { label: "Skipped", value: result.skipped, class: "text-gray-500" },
              {
                label: "Alerts Triggered",
                value: result.alerts_triggered,
                class: result.alerts_triggered > 0 ? "text-red-600 font-extrabold" : "",
              },
            ].map(({ label, value, class: customClass }) => (
              <div key={label} className="rounded-xl border p-4 text-center" style={{ borderColor: "var(--border-default)" }}>
                <p className={cn("text-2xl font-bold font-mono-soc", customClass)}>{value.toLocaleString()}</p>
                <p className="text-[11px] font-semibold uppercase tracking-wider mt-1.5" style={{ color: "var(--text-muted)" }}>{label}</p>
              </div>
            ))}
          </div>
          
          <div className="flex gap-3 pt-2">
            <Link to="/" className="flex-1">
              <button className="btn-primary w-full flex items-center justify-center gap-2 py-3 rounded-xl font-bold text-sm text-white">
                View SOC Dashboard <ArrowRight className="h-4.5 w-4.5" />
              </button>
            </Link>
            <button
              onClick={reset}
              className="px-5 py-3 rounded-xl border font-bold text-sm transition-all hover:bg-gray-50"
              style={{ borderColor: "var(--border-default)", color: "var(--text-secondary)" }}
            >
              Upload Another
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
