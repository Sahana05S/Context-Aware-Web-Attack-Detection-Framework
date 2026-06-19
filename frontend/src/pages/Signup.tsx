import { useState, FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldAlert, Eye, EyeOff, UserPlus } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export function Signup() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [username, setUsername]     = useState('');
  const [email,    setEmail]        = useState('');
  const [password, setPassword]     = useState('');
  const [confirm,  setConfirm]      = useState('');
  const [showPass, setShowPass]     = useState(false);
  const [error,    setError]        = useState<string | null>(null);
  const [loading,  setLoading]      = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== confirm) { setError('Passwords do not match'); return; }
    if (password.length < 8)  { setError('Password must be at least 8 characters'); return; }
    setLoading(true);
    try {
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/api/v1/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: username,
          email: email,
          password: password
        })
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || 'Registration failed');
      }

      const data = await response.json();
      login(data.access_token);
      navigate('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #F5F3FF 0%, #EDE9FF 50%, #DAD2FF 100%)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '20px', fontFamily: 'Inter, sans-serif'
    }}>
      <div style={{ width: '100%', maxWidth: 440 }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: 56, height: 56, borderRadius: 16,
            background: '#493D9E', marginBottom: 14, boxShadow: '0 8px 24px rgba(73,61,158,0.35)'
          }}>
            <ShieldAlert size={28} color="white" />
          </div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#1A1433', margin: 0 }}>Create Account</h1>
          <p style={{ fontSize: '0.875rem', color: '#7B7599', marginTop: 4 }}>Join the SecureEye platform</p>
        </div>

        {/* Card */}
        <div style={{
          background: 'white', borderRadius: 16, padding: '32px',
          boxShadow: '0 8px 40px rgba(73,61,158,0.12)',
          border: '1px solid #E4DFFF'
        }}>
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Username */}
            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#4B4569', marginBottom: 5 }}>Username</label>
              <input id="reg-username" type="text" value={username} onChange={e => setUsername(e.target.value)}
                placeholder="Choose a username" required className="input-field" />
            </div>

            {/* Email */}
            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#4B4569', marginBottom: 5 }}>Email</label>
              <input id="reg-email" type="email" value={email} onChange={e => setEmail(e.target.value)}
                placeholder="your@email.com" required className="input-field" />
            </div>

            {/* Password */}
            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#4B4569', marginBottom: 5 }}>Password</label>
              <div style={{ position: 'relative' }}>
                <input id="reg-password" type={showPass ? 'text' : 'password'} value={password}
                  onChange={e => setPassword(e.target.value)} placeholder="Min 8 characters"
                  required className="input-field" style={{ paddingRight: 42 }} />
                <button type="button" onClick={() => setShowPass(v => !v)}
                  style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#7B7599' }}>
                  {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Confirm */}
            <div>
              <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#4B4569', marginBottom: 5 }}>Confirm Password</label>
              <input id="reg-confirm" type={showPass ? 'text' : 'password'} value={confirm}
                onChange={e => setConfirm(e.target.value)} placeholder="Repeat password"
                required className="input-field" />
            </div>

            {/* Error */}
            {error && (
              <div style={{ background: '#FEE2E2', border: '1px solid #FECACA', borderRadius: 8, padding: '10px 14px', fontSize: '0.82rem', color: '#991B1B' }}>
                {error}
              </div>
            )}

            {/* Submit */}
            <button id="reg-submit-btn" type="submit" disabled={loading}
              className="btn-primary"
              style={{ width: '100%', justifyContent: 'center', padding: '11px', fontSize: '0.9rem', marginTop: 4 }}>
              {loading ? (
                <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 16, height: 16, border: '2px solid rgba(255,255,255,0.4)', borderTopColor: 'white', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' }} />
                  Creating account...
                </span>
              ) : (
                <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <UserPlus size={16} /> Create Account
                </span>
              )}
            </button>
          </form>

          <p style={{ textAlign: 'center', marginTop: 22, fontSize: '0.82rem', color: '#7B7599' }}>
            Already have an account?{' '}
            <Link to="/login" style={{ color: '#493D9E', fontWeight: 600, textDecoration: 'none' }}>Sign In</Link>
          </p>
        </div>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
