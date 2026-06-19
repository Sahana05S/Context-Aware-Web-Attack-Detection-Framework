import { LucideIcon } from 'lucide-react';

interface StatsCardProps {
  title:       string;
  value:       string | number;
  icon:        LucideIcon;
  description?: string;
  accentColor?: string;
  trend?:      { value: number; label: string };
}

export function StatsCard({ title, value, icon: Icon, description, accentColor, trend }: StatsCardProps) {
  const color = accentColor || 'var(--purple-dark)';

  return (
    <div className="stat-card">
      {/* Icon + Title */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 14 }}>
        <div>
          <p style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 6 }}>
            {title}
          </p>
          <p className="metric-value" style={{ fontSize: '1.9rem', lineHeight: 1, color: 'var(--text-primary)' }}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
        </div>
        <div style={{
          width: 42, height: 42, borderRadius: 10,
          background: `${color}18`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0
        }}>
          <Icon size={20} color={color} />
        </div>
      </div>

      {/* Description / Trend */}
      {(description || trend) && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          {description && (
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{description}</p>
          )}
          {trend && (
            <span style={{
              fontSize: '0.72rem', fontWeight: 600,
              color: trend.value >= 0 ? 'var(--sev-critical)' : 'var(--sev-low)',
              background: trend.value >= 0 ? '#FEE2E2' : '#D1FAE5',
              padding: '2px 8px', borderRadius: 9999
            }}>
              {trend.value >= 0 ? '↑' : '↓'} {Math.abs(trend.value)}%
            </span>
          )}
        </div>
      )}
    </div>
  );
}
