import { useState } from 'react';
import { Brain, Zap, AlertTriangle, CheckCircle, Clock, Shield } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface AnalysisResult {
  is_attack:    boolean;
  attack_type:  string;
  confidence:   number;
  severity:     string;
  ai_score:     number;
  explanation:  string;
  intent:       string;
  zero_day_risk: boolean;
  model_used:   string;
}

interface AnalysisHistory {
  id:         number;
  url:        string;
  method:     string;
  ip:         string;
  result:     AnalysisResult;
  timestamp:  string;
}

const BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const SEVERITY_STYLES: Record<string, { bg: string; color: string; badge: string }> = {
  CRITICAL: { bg: '#FEE2E2', color: '#991B1B', badge: 'badge-critical' },
  HIGH:     { bg: '#FED7AA', color: '#9A3412', badge: 'badge-high' },
  MEDIUM:   { bg: '#FEF3C7', color: '#92400E', badge: 'badge-medium' },
  LOW:      { bg: '#D1FAE5', color: '#065F46', badge: 'badge-low' },
};

let historyCounter = 0;

export function AIAnalysis() {
  const [url,     setUrl]     = useState('');
  const [method,  setMethod]  = useState('GET');
  const [ip,      setIp]      = useState('1.2.3.4');
  const [status,  setStatus]  = useState(200);
  const [ua,      setUa]      = useState('');
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState<AnalysisResult | null>(null);
  const [error,   setError]   = useState<string | null>(null);
  const [history, setHistory] = useState<AnalysisHistory[]>([]);

  const analyze = async () => {
    if (!url.trim()) { setError('Please enter a URL to analyze'); return; }
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const token = localStorage.getItem('access_token');
      const res = await fetch(`${BASE}/api/v1/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        },
        body: JSON.stringify({ url, method, remote_ip: ip, status, user_agent: ua }),
      });

      if (!res.ok) throw new Error(`API error ${res.status}`);
      const data = await res.json();
      setResult(data.analysis);

      // Add to history
      setHistory(prev => [{
        id: ++historyCounter,
        url: url.slice(0, 80),
        method, ip,
        result: data.analysis,
        timestamp: new Date().toLocaleTimeString()
      }, ...prev.slice(0, 9)]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const sevStyle = result ? (SEVERITY_STYLES[result.severity] || SEVERITY_STYLES.LOW) : null;

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 6 }}>
          <div style={{ width: 42, height: 42, borderRadius: 10, background: '#493D9E', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Brain size={22} color="white" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#1A1433', margin: 0 }}>AI Intent Analyzer</h1>
            <p style={{ fontSize: '0.82rem', color: '#7B7599', margin: 0 }}>LLM-powered context-aware attack detection</p>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 20 }}>
        {/* Input Panel */}
        <div className="card" style={{ padding: 24 }}>
          <h2 style={{ fontSize: '0.875rem', fontWeight: 700, color: '#1A1433', marginBottom: 18, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Zap size={16} color="#493D9E" /> Analyze Request
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 14 }}>
            {/* URL */}
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: '#7B7599', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>URL / Path *</label>
              <input
                id="ai-url-input"
                type="text"
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="e.g. /api/users?id=1 OR 1=1--"
                className="input-field font-mono-soc"
                onKeyDown={e => e.key === 'Enter' && analyze()}
              />
            </div>

            {/* Method + Status + IP */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: '#7B7599', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Method</label>
                <select value={method} onChange={e => setMethod(e.target.value)} className="input-field">
                  {['GET','POST','PUT','DELETE','PATCH','OPTIONS'].map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: '#7B7599', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Status</label>
                <input type="number" value={status} onChange={e => setStatus(+e.target.value)} className="input-field" />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: '#7B7599', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Client IP</label>
                <input type="text" value={ip} onChange={e => setIp(e.target.value)} className="input-field font-mono-soc" placeholder="1.2.3.4" />
              </div>
            </div>

            {/* User Agent */}
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: '#7B7599', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em' }}>User Agent (optional)</label>
              <input type="text" value={ua} onChange={e => setUa(e.target.value)} placeholder="e.g. Mozilla/5.0 or sqlmap/1.7" className="input-field" />
            </div>

            {/* Error */}
            {error && <div style={{ background: '#FEE2E2', border: '1px solid #FECACA', borderRadius: 8, padding: '10px 14px', fontSize: '0.82rem', color: '#991B1B', display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={14} /> {error}
            </div>}

            {/* Analyze Button */}
            <button id="analyze-btn" onClick={analyze} disabled={loading} className="btn-primary"
              style={{ justifyContent: 'center', padding: '11px', fontSize: '0.9rem' }}>
              {loading ? (
                <><span style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.4)', borderTopColor: 'white', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block', marginRight: 8 }} />Analyzing...</>
              ) : (
                <><Brain size={16} style={{ marginRight: 8 }} />Run AI Analysis</>
              )}
            </button>
          </div>
        </div>

        {/* Result Panel */}
        <AnimatePresence>
          {result && sevStyle && (
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="card"
              style={{ padding: 24, borderLeft: `4px solid ${sevStyle.color}` }}
            >
              {/* Result Header */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  {result.is_attack ? <AlertTriangle size={22} color={sevStyle.color} /> : <CheckCircle size={22} color="#16A34A" />}
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '1.1rem', color: '#1A1433' }}>
                      {result.is_attack ? result.attack_type : 'Clean Request'}
                    </div>
                    <div style={{ fontSize: '0.78rem', color: '#7B7599', marginTop: 2 }}>
                      Model: <span style={{ fontFamily: 'JetBrains Mono, monospace', color: '#493D9E' }}>{result.model_used}</span>
                    </div>
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <span className={`badge badge-${result.severity.toLowerCase()}`}>{result.severity}</span>
                  {result.zero_day_risk && (
                    <div style={{ marginTop: 6, fontSize: '0.7rem', color: '#EA580C', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4, justifyContent: 'flex-end' }}>
                      <Shield size={11} /> Zero-Day Risk
                    </div>
                  )}
                </div>
              </div>

              {/* Scores */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16, marginBottom: 20 }}>
                <div style={{ background: '#F5F3FF', borderRadius: 10, padding: '14px 16px' }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#7B7599', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>AI Risk Score</div>
                  <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#493D9E' }}>{Math.round(result.ai_score * 100)}</div>
                  <div className="risk-bar-track" style={{ marginTop: 8 }}>
                    <div className="risk-bar-fill" style={{ width: `${result.ai_score * 100}%` }} />
                  </div>
                </div>
                <div style={{ background: '#F5F3FF', borderRadius: 10, padding: '14px 16px' }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#7B7599', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>Confidence</div>
                  <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#493D9E' }}>{Math.round(result.confidence * 100)}%</div>
                  <div className="risk-bar-track" style={{ marginTop: 8 }}>
                    <div className="risk-bar-fill" style={{ width: `${result.confidence * 100}%` }} />
                  </div>
                </div>
              </div>

              {/* AI Insight */}
              <div className="ai-insight">
                <div className="ai-insight-label"><Brain size={12} /> AI Explanation</div>
                <p className="ai-insight-text">{result.explanation}</p>
              </div>

              {/* Intent */}
              <div style={{ marginTop: 14, padding: '12px 16px', background: result.is_attack ? '#FEF3C7' : '#D1FAE5', borderRadius: 10 }}>
                <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: result.is_attack ? '#92400E' : '#065F46', marginBottom: 4 }}>
                  Detected Intent
                </div>
                <p style={{ fontSize: '0.85rem', color: result.is_attack ? '#92400E' : '#065F46', margin: 0 }}>{result.intent}</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* History */}
        {history.length > 0 && (
          <div className="card" style={{ padding: 24 }}>
            <h2 style={{ fontSize: '0.875rem', fontWeight: 700, color: '#1A1433', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Clock size={15} color="#493D9E" /> Analysis History
            </h2>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th><th>Method</th><th>URL</th><th>Result</th><th>Score</th>
                </tr>
              </thead>
              <tbody>
                {history.map(h => (
                  <tr key={h.id}>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: '#7B7599' }}>{h.timestamp}</td>
                    <td><span style={{ fontWeight: 600, color: '#493D9E', fontSize: '0.78rem' }}>{h.method}</span></td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={h.url}>{h.url}</td>
                    <td>
                      <span className={`badge badge-${h.result.severity.toLowerCase()}`}>
                        {h.result.is_attack ? h.result.attack_type : 'Clean'}
                      </span>
                    </td>
                    <td style={{ fontWeight: 700, color: '#493D9E' }}>{Math.round(h.result.ai_score * 100)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
