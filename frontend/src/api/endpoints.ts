import { fetchClient } from "./client";
import { AlertListResponse, IPDetail, OverviewStats, StatusResponse, AIAnalysisResult, FlowAnalysis, AISummaryResponse } from "./types";

export const api = {
    health: () => fetchClient<StatusResponse>("/health"),

    alerts: (params: { limit?: number; offset?: number; since_minutes?: number; severity?: string } = {}) => {
        const query = new URLSearchParams();
        if (params.limit) query.append("limit", params.limit.toString());
        if (params.offset !== undefined) query.append("offset", params.offset.toString());
        if (params.since_minutes) query.append("since_minutes", params.since_minutes.toString());
        if (params.severity) query.append("severity", params.severity);
        return fetchClient<AlertListResponse>(`/alerts?${query.toString()}`);
    },

    overview: (since_minutes: number = 1440) => {
        return fetchClient<OverviewStats>(`/stats/overview?since_minutes=${since_minutes}`);
    },

    ipDetail: (ip: string, since_hours: number = 24) => {
        return fetchClient<IPDetail>(`/ips/${ip}?since_hours=${since_hours}`);
    },

    analyzeRequest: (params: { url: string; method: string; status: number; remote_ip: string; user_agent?: string }) => {
        return fetchClient<{ success: boolean; analysis: AIAnalysisResult }>("/analyze", {
            method: "POST",
            body: JSON.stringify(params)
        });
    },

    flowAnalysis: (ip: string) => {
        return fetchClient<FlowAnalysis>(`/analyze/flow/${ip}`);
    },

    aiStatus: () => {
        return fetchClient<{ ai_enabled: boolean; model: string; status: string; detail?: string }>("/analyze/status");
    },

    aiSummary: (since_minutes: number = 1440) => {
        return fetchClient<AISummaryResponse>(`/stats/ai-summary?since_minutes=${since_minutes}`);
    }
};
