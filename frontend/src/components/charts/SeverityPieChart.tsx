import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend } from "recharts";

interface SeverityPieChartProps {
    data: Record<string, number>;
}

const COLORS: Record<string, string> = {
    CRITICAL: "#e13d3d",
    HIGH:     "#e13d3d",
    MEDIUM:   "#f2c14a",
    LOW:      "#73bf69",
    INFO:     "#73bf69",
};

const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
        return (
            <div style={{ background: 'hsl(225 16% 13%)', border: '1px solid hsl(225 12% 20%)', borderRadius: 4, padding: '8px 12px' }}>
                <p style={{ color: COLORS[payload[0].name] || '#888', fontSize: 12 }}>
                    {payload[0].name}: <strong>{payload[0].value}</strong>
                </p>
            </div>
        );
    }
    return null;
};

const renderLegend = (props: any) => {
    const { payload } = props;
    return (
        <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 mt-2">
            {payload.map((entry: any) => (
                <div key={entry.value} className="flex items-center gap-1.5">
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: entry.color, display: 'inline-block' }} />
                    <span style={{ fontSize: 11, color: 'hsl(215 15% 50%)' }}>{entry.value}</span>
                </div>
            ))}
        </div>
    );
};

export function SeverityPieChart({ data }: SeverityPieChartProps) {
    const chartData = Object.entries(data)
        .map(([name, value]) => ({ name, value }))
        .filter(d => d.value > 0);
    const isEmpty = chartData.length === 0;

    return (
        <div className="soc-panel p-5">
            <h3 className="text-xs font-semibold tracking-widest uppercase mb-4" style={{ color: 'hsl(215 15% 45%)' }}>
                Severity Distribution
            </h3>
            <div className="h-[260px] w-full">
                {isEmpty ? (
                    <div className="flex h-full items-center justify-center text-sm" style={{ color: 'hsl(215 15% 35%)' }}>
                        No alerts
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                            <Pie
                                data={chartData}
                                cx="50%"
                                cy="46%"
                                innerRadius={58}
                                outerRadius={82}
                                paddingAngle={3}
                                dataKey="value"
                                strokeWidth={0}
                            >
                                {chartData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[entry.name] || "#888"} />
                                ))}
                            </Pie>
                            <Tooltip content={<CustomTooltip />} />
                            <Legend content={renderLegend} />
                        </PieChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}
