import { useState, useEffect } from 'react';
import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom';
import {
  ShieldAlert, LayoutDashboard, BellRing, UploadCloud,
  Radio, LogOut, Brain, Activity, Menu
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

const NAV_ITEMS = [
  { label: 'Dashboard',    path: '/dashboard', icon: LayoutDashboard },
  { label: 'Alerts',       path: '/alerts',    icon: BellRing },
  { label: 'Live Monitor', path: '/live',      icon: Radio },
  { label: 'Upload Logs',  path: '/upload',    icon: UploadCloud },
  { label: 'AI Analysis',  path: '/ai',        icon: Brain },
];

export function Layout() {
  const location  = useLocation();
  const navigate  = useNavigate();
  const { logout }            = useAuth();
  const [health, setHealth]   = useState<'ok' | 'error' | 'loading' | 'waking'>('loading');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    let retryCount = 0;
    let intervalId: ReturnType<typeof setInterval>;

    const check = async () => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000);
        const res = await fetch(
          `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/api/v1/health`,
          { signal: controller.signal }
        );
        clearTimeout(timeout);
        if (res.ok) {
          setHealth('ok');
          retryCount = 0;
          // Back to normal 60s polling once healthy
          clearInterval(intervalId);
          intervalId = setInterval(check, 60000);
        } else {
          setHealth('error');
        }
      } catch {
        retryCount++;
        // First few failures = Render cold-start waking up, not a real error
        setHealth(retryCount <= 6 ? 'waking' : 'error');
        // Retry every 10s when unhealthy
        clearInterval(intervalId);
        intervalId = setInterval(check, 10000);
      }
    };

    check();
    intervalId = setInterval(check, 60000);
    return () => clearInterval(intervalId);
  }, []);

  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div style={{ padding: '24px 20px 20px', borderBottom: '1px solid rgba(255,255,255,0.12)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: 'rgba(255,255,255,0.15)',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <ShieldAlert size={18} color="white" />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '1rem', color: 'white', lineHeight: 1.2 }}>SecureEye</div>
            <div style={{ fontSize: '0.65rem', color: 'rgba(255,255,255,0.6)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>WAF Detection</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ padding: '16px 12px', flex: 1, display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div style={{ fontSize: '0.65rem', color: 'rgba(255,255,255,0.45)', textTransform: 'uppercase', letterSpacing: '0.1em', padding: '4px 8px 10px', fontWeight: 600 }}>
          Navigation
        </div>
        {NAV_ITEMS.map(({ label, path, icon: Icon }) => {
          const isActive = location.pathname === path || location.pathname.startsWith(path + '/');
          return (
            <Link
              key={path}
              to={path}
              onClick={() => setSidebarOpen(false)}
              className="sidebar-link"
              style={isActive ? {
                background: 'rgba(255,255,255,0.18)',
                color: '#fff',
                boxShadow: 'inset 3px 0 0 #B2A5FF'
              } : {}}
            >
              <Icon size={16} />
              {label}
              {path === '/live' && isActive && (
                <span style={{ marginLeft: 'auto', width: 8, height: 8, borderRadius: '50%', background: '#4ADE80', animation: 'pulse 2s infinite' }} />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Bottom */}
      <div style={{ padding: '12px 12px 20px', borderTop: '1px solid rgba(255,255,255,0.10)' }}>
        {/* API Status */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '8px 10px', borderRadius: 8,
          background: 'rgba(255,255,255,0.07)',
          marginBottom: 10
        }}>
          <Activity size={12} color={health === 'ok' ? '#4ADE80' : health === 'waking' ? '#FBBF24' : '#F87171'}
            style={health === 'waking' ? { animation: 'pulse 1s infinite' } : {}}
          />
          <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.6)' }}>API</span>
          <span style={{
            fontSize: '0.72rem', fontWeight: 600, marginLeft: 'auto', textTransform: 'uppercase',
            color: health === 'ok' ? '#4ADE80' : health === 'waking' ? '#FBBF24' : '#F87171'
          }}>
            {health === 'waking' ? 'Waking…' : health}
          </span>
        </div>

        {/* Logout */}
        <div style={{ display: 'flex' }}>
          <button
            onClick={() => { logout(); navigate('/login'); }}
            title="Sign Out"
            style={{ flex: 1, padding: '10px', borderRadius: 8, background: 'rgba(255,255,255,0.08)', border: 'none', color: 'rgba(255,255,255,0.7)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', transition: 'all 0.15s', fontSize: '0.8rem', fontWeight: 600 }}
            className="hover:bg-white/15"
          >
            <LogOut size={15} />
            Sign Out
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-page)' }}>
      {/* Sidebar Overlay */}
      {sidebarOpen && (
        <div
          style={{ position: 'fixed', inset: 0, zIndex: 40, background: 'rgba(0,0,0,0.4)' }}
          onClick={() => setSidebarOpen(false)}
        />
      )}
      
      {/* Collapsible Sidebar Drawer */}
      <aside
        style={{
          position: 'fixed', top: 0, left: sidebarOpen ? 0 : -260, bottom: 0,
          width: 240, zIndex: 50,
          background: 'var(--purple-dark)',
          transition: 'left 0.25s ease',
          display: 'flex', flexDirection: 'column'
        }}
      >
        <SidebarContent />
      </aside>

      {/* Main Content Area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Top header bar */}
        <header style={{
          background: 'white', borderBottom: '1px solid var(--border-default)',
          padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12,
          position: 'sticky', top: 0, zIndex: 30
        }}>
          <button onClick={() => setSidebarOpen(true)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--purple-dark)' }}>
            <Menu size={22} />
          </button>
          <span style={{ fontWeight: 700, color: 'var(--purple-dark)', fontSize: '1rem' }}>SecureEye</span>
        </header>

        {/* Page content */}
        <main style={{ flex: 1, padding: '28px 32px', overflowY: 'auto' }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
