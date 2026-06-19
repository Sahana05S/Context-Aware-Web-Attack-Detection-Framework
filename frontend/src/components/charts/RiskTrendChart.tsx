import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from "recharts";
import { TrendPoint } from "../../api/types";

interface RiskTrendChartProps {
    data: TrendPoint[];
}

const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
        return (
            <div style={{ background: 'hsl(225 16% 13%)', border: '1px solid hsl(225 12% 20%)', borderRadius: 4, padding: '8px 12px' }}>
                <p style={{ color: 'hsl(215 15% 55%)', fontSize: 11, marginBottom: 4 }}>{label}</p>
                {payload.map((p: any) => (
                    <p key={p.name} style={{ color: p.color, fontSize: 12, margin: 0 }}>
                        {p.name}: <strong>{p.value}</strong>
                    </p>
                ))}
            </div>
        );
    }
    return null;
};

export function RiskTrendChart({ data }: RiskTrendChartProps) {
    const isEmpty = !data || data.length === 0;

    return (
        <div className="soc-panel p-5">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-xs font-semibold tracking-widest uppercase" style={{ color: 'hsl(215 15% 45%)' }}>
                    Risk Trend — Avg vs Peak
                </h3>
            </div>
            <div className="h-[260px] w-full">
                {isEmpty ? (
                    <div className="flex h-full items-center justify-center text-sm" style={{ color: 'hsl(215 15% 35%)' }}>
                        No trend data available
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={data} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="hsl(225 12% 18%)" vertical={false} />
                            <XAxis
                                dataKey="bucket"
                                stroke="hsl(215 15% 30%)"
                                fontSize={10}
                                tickLine={false}
                                axisLine={false}
                                tickFormatter={(val) => val.split('T')[1]?.substring(0, 5) || val}
                            />
                            <YAxis
                                stroke="hsl(215 15% 30%)"
                                fontSize={10}
                                tickLine={false}
                                axisLine={false}
                            />
                            <Tooltip content={<CustomTooltip />} />
                            <Legend
                                wrapperStyle={{ fontSize: 11, color: 'hsl(215 15% 50%)' }}
                            />
                            <Line type="monotone" dataKey="avg_risk" stroke="#AD49E1" strokeWidth={2} dot={false} name="Avg Risk" />
                            <Line type="monotone" dataKey="peak_risk" stroke="#EBD3F8" strokeWidth={2} dot={false} name="Peak Risk" />
                        </LineChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}
