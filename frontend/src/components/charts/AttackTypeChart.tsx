import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from "recharts";

interface AttackTypeChartProps {
    data: Record<string, number>;
}

// Cycle through vivid SOC chart colors (Custom Purple Palette)
const BAR_COLORS = ['#AD49E1', '#7A1CAC', '#EBD3F8', '#9932cc', '#ba55d3', '#8a2be2'];

const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
        return (
            <div style={{ background: '#ffffff', border: '1px solid var(--border-default)', borderRadius: 4, padding: '8px 12px', boxShadow: '0 4px 12px rgba(73,61,158,0.1)' }}>
                <p style={{ color: payload[0].color, fontSize: 12, fontWeight: 500 }}>
                    {payload[0].payload.name}: <strong style={{ color: '#1A1433' }}>{payload[0].value}</strong>
                </p>
            </div>
        );
    }
    return null;
};

export function AttackTypeChart({ data }: AttackTypeChartProps) {
    const chartData = Object.entries(data)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value);
    const isEmpty = chartData.length === 0;

    return (
        <div className="soc-panel p-5">
            <h3 className="text-xs font-semibold tracking-widest uppercase mb-4" style={{ color: 'var(--text-muted)' }}>
                Attack Types
            </h3>
            <div className="h-[260px] w-full">
                {isEmpty ? (
                    <div className="flex h-full items-center justify-center text-sm" style={{ color: 'var(--text-muted)' }}>
                        No attack data
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 10, left: 50, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#F1F0F5" horizontal={false} />
                            <XAxis type="number" stroke="var(--text-muted)" fontSize={10} tickLine={false} axisLine={false} />
                            <YAxis
                                dataKey="name"
                                type="category"
                                stroke="var(--text-muted)"
                                fontSize={10}
                                tickLine={false}
                                axisLine={false}
                                width={50}
                            />
                            <Tooltip cursor={{ fill: '#F5F3FF' }} content={<CustomTooltip />} />
                            <Bar dataKey="value" radius={[0, 3, 3, 0]} barSize={16}>
                                {chartData.map((_entry, index) => (
                                    <Cell key={`cell-${index}`} fill={BAR_COLORS[index % BAR_COLORS.length]} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}
