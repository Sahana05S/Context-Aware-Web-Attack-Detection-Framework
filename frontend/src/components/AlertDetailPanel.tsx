import React, { useState } from 'react';
import { AlertSummary } from '../api/types';
import { ShieldAlert, Shield, Cpu, Activity, Brain, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react';
import { motion } from 'framer-motion';

interface AlertDetailPanelProps {
    alert: AlertSummary;
}

const CONSEQUENCES: Record<string, string> = {
    "Path Traversal": "An attacker escaping the web directory could read sensitive server files (like /etc/passwd or configuration files), potentially exposing credentials or system architecture.",
    "SQL Injection": "Successful SQLi allows the attacker to read, modify, or delete backend database records. It can lead to complete data compromise or authentication bypass.",
    "Cross-Site Scripting (XSS)": "XSS allows attackers to execute malicious scripts in the browsers of other users, which can be used to steal session cookies, deface the site, or redirect users.",
    "Command Injection": "Command injection is extremely critical as it allows the attacker to execute arbitrary OS commands on the host server, often leading to a full system compromise.",
    "Reconnaissance": "Reconnaissance activities indicate an attacker is mapping your application's structure to find vulnerable endpoints for a future targeted attack.",
    "Bot/Automation": "Automated tools (scanners/bots) are probing your application for known vulnerabilities at scale.",
    "Login Brute Force": "The attacker is systematically trying to guess valid credentials to gain unauthorized access to an account.",
    "Coordinated Scan / Burst": "A high-volume distributed probe attempt to map or overwhelm your application."
};

function copyToClipboard(text: string, setCopied: (val: boolean) => void) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
}

export const AlertDetailPanel: React.FC<AlertDetailPanelProps> = ({ alert }) => {
    const [copiedUrl, setCopiedUrl] = useState(false);
    const [showFullUrl, setShowFullUrl] = useState(false);
    const [copiedUa, setCopiedUa] = useState(false);

    // Determine attack base type from title for consequences
    const attackType = Object.keys(CONSEQUENCES).find(k => alert.title.includes(k)) || "Web Attack";
    const consequence = CONSEQUENCES[attackType] || "This activity represents an attempt to bypass security controls or abuse application functionality.";

    // Parse signals
    let signals: Record<string, number> = {};
    try {
        if (alert.signal_breakdown) {
            signals = JSON.parse(alert.signal_breakdown);
        }
    } catch (e) {
        // ignore
    }

    const hasAI = !!alert.ai_explanation;
    
    let fallbackReasons: string[] = [];
    if (!hasAI && alert.context_reasons) {
        try {
            const parsed = JSON.parse(alert.context_reasons);
            if (Array.isArray(parsed)) fallbackReasons = parsed;
            else fallbackReasons = [alert.context_reasons];
        } catch {
            fallbackReasons = [alert.context_reasons];
        }
    }

    // Format fallback strings slightly for better readability
    fallbackReasons = fallbackReasons.map(r => {
        if (r.startsWith("Rule: ")) return r.replace("Rule: ", "Pattern Engine matched rule: ").replace("(Severity.H)", "(Severity: HIGH)").replace("(Severity.M)", "(Severity: MEDIUM)").replace("(Severity.C)", "(Severity: CRITICAL)");
        if (r.startsWith("ML: ")) return r.replace("ML: ", "ML Classifier flagged an anomaly (Score: ").replace(" model=True", ")") + ")";
        return r;
    });

    const displayUrl = alert.url || "N/A";
    const isLongUrl = displayUrl.length > 150;
    const truncatedUrl = isLongUrl && !showFullUrl ? displayUrl.substring(0, 150) + "..." : displayUrl;

    return (
        <div className="p-6 bg-[#FCFBFF] text-sm" style={{ borderTop: "1px solid var(--border-default)" }}>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                
                {/* LEFT COLUMN */}
                <div className="space-y-6">
                    {/* PAYLOAD SECTION */}
                    <div className="space-y-2">
                        <h4 className="text-[10px] font-bold tracking-widest uppercase" style={{ color: "var(--text-muted)" }}>
                            Detected Payload
                        </h4>
                        
                        <div className="bg-white border rounded-lg p-3 shadow-sm relative group" style={{ borderColor: "var(--border-default)" }}>
                            <div className="flex justify-between items-start mb-1">
                                <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wide">Request URL</span>
                                <button onClick={() => copyToClipboard(displayUrl, setCopiedUrl)} className="text-gray-400 hover:text-gray-700 transition-colors">
                                    {copiedUrl ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
                                </button>
                            </div>
                            <div className="font-mono text-xs break-all" style={{ color: "#e13d3d" }}>
                                {truncatedUrl}
                            </div>
                            {isLongUrl && (
                                <button 
                                    onClick={() => setShowFullUrl(!showFullUrl)}
                                    className="mt-2 text-[10px] font-semibold text-[#493D9E] flex items-center gap-1 hover:underline"
                                >
                                    {showFullUrl ? <><ChevronUp size={12}/> Show less</> : <><ChevronDown size={12}/> Show full payload</>}
                                </button>
                            )}
                        </div>

                        {alert.user_agent && (
                            <div className="bg-white border rounded-lg p-3 shadow-sm relative group" style={{ borderColor: "var(--border-default)" }}>
                                <div className="flex justify-between items-start mb-1">
                                    <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wide">User Agent</span>
                                    <button onClick={() => copyToClipboard(alert.user_agent!, setCopiedUa)} className="text-gray-400 hover:text-gray-700 transition-colors">
                                        {copiedUa ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
                                    </button>
                                </div>
                                <div className="font-mono text-[11px] text-gray-600 break-all">
                                    {alert.user_agent}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* AI EXPLANATION SECTION */}
                    <div className="space-y-2">
                        <h4 className="text-[10px] font-bold tracking-widest uppercase flex items-center gap-2" style={{ color: "var(--text-muted)" }}>
                            What is happening (Plain English)
                        </h4>
                        <div className="bg-[#F5F3FF] border border-[#E4DFFF] rounded-lg p-4 shadow-sm relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-1 h-full bg-[#B2A5FF]"></div>
                            <div className="flex gap-3">
                                <div className="mt-0.5">
                                    {hasAI ? <Brain className="text-[#493D9E]" size={18} /> : <ShieldAlert className="text-[#f2a93b]" size={18} />}
                                </div>
                                <div>
                                    {!hasAI && fallbackReasons.length > 0 ? (
                                        <ul className="space-y-1.5 mt-1 text-[11px]" style={{ color: "var(--text-secondary)" }}>
                                            {fallbackReasons.map((r, i) => (
                                                <li key={i} className="flex items-start gap-2">
                                                    <span className="text-[#B2A5FF] font-bold mt-0.5">•</span>
                                                    <span>{r}</span>
                                                </li>
                                            ))}
                                        </ul>
                                    ) : (
                                        <p className="text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                                            {alert.ai_explanation || "A heuristic rule was triggered indicating malicious behavior."}
                                        </p>
                                    )}
                                    <div className="mt-2 text-[9px] font-bold tracking-wide uppercase text-[#B2A5FF]">
                                        {hasAI ? "AI Judge Analysis" : "Pattern-based Explanation"}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* RIGHT COLUMN */}
                <div className="space-y-6">
                    {/* SIGNAL BREAKDOWN SECTION */}
                    <div className="space-y-2">
                        <h4 className="text-[10px] font-bold tracking-widest uppercase" style={{ color: "var(--text-muted)" }}>
                            Detection Signals
                        </h4>
                        <div className="bg-white border rounded-lg shadow-sm overflow-hidden" style={{ borderColor: "var(--border-default)" }}>
                            {/* Rule Signal */}
                            <div className="p-3 border-b flex items-center justify-between" style={{ borderColor: "var(--border-default)" }}>
                                <div className="flex items-center gap-3">
                                    <div className="p-1.5 rounded bg-purple-50 text-purple-600"><Shield size={14} /></div>
                                    <div>
                                        <div className="text-xs font-semibold text-gray-800">Rule Engine</div>
                                        <div className="text-[10px] text-gray-500">Signatures & Patterns</div>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-sm font-bold text-gray-800">{Math.round((signals.rule_component || 0) * 100)} <span className="text-[10px] font-normal text-gray-500">pts</span></div>
                                </div>
                            </div>

                            {/* Behavior Signal */}
                            <div className="p-3 border-b flex items-center justify-between" style={{ borderColor: "var(--border-default)" }}>
                                <div className="flex items-center gap-3">
                                    <div className="p-1.5 rounded bg-blue-50 text-blue-600"><Activity size={14} /></div>
                                    <div>
                                        <div className="text-xs font-semibold text-gray-800">Behavioral</div>
                                        <div className="text-[10px] text-gray-500">Rate limits & Flow</div>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-sm font-bold text-gray-800">{Math.round(((signals.behavior_component || 0) + (signals.flow_violation_bonus ? signals.flow_violation_bonus / 100 : 0)) * 100)} <span className="text-[10px] font-normal text-gray-500">pts</span></div>
                                </div>
                            </div>

                            {/* ML Signal */}
                            <div className="p-3 border-b flex items-center justify-between" style={{ borderColor: "var(--border-default)" }}>
                                <div className="flex items-center gap-3">
                                    <div className="p-1.5 rounded bg-green-50 text-green-600"><Cpu size={14} /></div>
                                    <div>
                                        <div className="text-xs font-semibold text-gray-800">ML Classifier</div>
                                        <div className="text-[10px] text-gray-500">Statistical anomalies</div>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-sm font-bold text-gray-800">{Math.round((signals.ml_component || 0) * 100)} <span className="text-[10px] font-normal text-gray-500">pts</span></div>
                                </div>
                            </div>

                            {/* AI Judge Signal */}
                            <div className="p-3 border-b flex items-center justify-between" style={{ borderColor: "var(--border-default)" }}>
                                <div className="flex items-center gap-3">
                                    <div className="p-1.5 rounded bg-orange-50 text-orange-500"><Brain size={14} /></div>
                                    <div>
                                        <div className="text-xs font-semibold text-gray-800">AI Judge</div>
                                        <div className="text-[10px] text-gray-500">Contextual Intent</div>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-sm font-bold text-gray-800">{Math.round((signals.ai_component || 0) * 100)} <span className="text-[10px] font-normal text-gray-500">pts</span></div>
                                </div>
                            </div>
                            
                            {/* Context & Multi Bonus */}
                            {((signals.context_component || 0) > 0 || (signals.multi_match_bonus || 0) > 0) && (
                                <div className="p-3 bg-gray-50 flex items-center justify-between">
                                    <div className="text-xs text-gray-600 font-medium">Context & Bonuses</div>
                                    <div className="text-sm font-bold text-gray-800">
                                        {Math.round(((signals.context_component || 0) * 100) + (signals.multi_match_bonus || 0))} <span className="text-[10px] font-normal text-gray-500">pts</span>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* CONSEQUENCES SECTION */}
                    <div className="space-y-2">
                        <h4 className="text-[10px] font-bold tracking-widest uppercase" style={{ color: "var(--text-muted)" }}>
                            What could happen
                        </h4>
                        <div className="text-xs leading-relaxed p-3 bg-red-50 border border-red-100 rounded-lg text-red-900 shadow-sm">
                            <span className="font-semibold block mb-1">Potential Impact:</span>
                            {consequence}
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
};
