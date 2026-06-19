export class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
        super(message);
        this.status = status;
    }
}

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export async function fetchClient<T>(
    endpoint: string,
    options: RequestInit = {}
): Promise<T> {
    const url = `${BASE_URL}/api/v1${endpoint}`;

    try {
        const token = localStorage.getItem("access_token");
        const headers: Record<string, string> = {
            "Content-Type": "application/json",
            ...(options.headers as Record<string, string> || {}),
        };
        if (token) {
            headers["Authorization"] = `Bearer ${token}`;
        }

        const response = await fetch(url, {
            ...options,
            headers,
        });

        if (!response.ok) {
            if (response.status === 401) {
                localStorage.removeItem("access_token");
                window.location.href = "/login";
            }
            
            // Try to parse error message from JSON
            let errorMessage = `API Error: ${response.statusText}`;
            try {
                const errorData = await response.json();
                if (errorData.detail) errorMessage = errorData.detail;
            } catch {
                // Ignore JSON parse error, use status text
            }
            throw new ApiError(errorMessage, response.status);
        }

        return response.json() as Promise<T>;
    } catch (error) {
        if (error instanceof ApiError) throw error;
        throw new Error(error instanceof Error ? error.message : "Network error");
    }
}
