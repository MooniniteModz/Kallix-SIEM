import { useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { KeyRound, LogIn, CheckCircle } from 'lucide-react';
import KallixLogo from '../components/KallixLogo';
import { api } from '../api';

export default function ResetPassword() {
  const [searchParams]  = useSearchParams();
  const navigate        = useNavigate();
  const token           = searchParams.get('token') || '';

  const [newPassword, setNewPassword]     = useState('');
  const [confirmPassword, setConfirm]     = useState('');
  const [error, setError]                 = useState('');
  const [loading, setLoading]             = useState(false);
  const [done, setDone]                   = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');

    if (!token) {
      setError('No reset token found. Please request a new reset link.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    if (newPassword.length < 12) {
      setError('Password must be at least 12 characters.');
      return;
    }

    setLoading(true);
    try {
      await api.resetPassword(token, newPassword);
      setDone(true);
    } catch (err) {
      setError(err.message || 'Reset failed. The link may have expired.');
    }
    setLoading(false);
  }

  if (done) {
    return (
      <div className="login-container">
        <div className="login-card">
          <div className="login-brand">
            <div className="login-brand-icon" style={{ color: 'var(--green)' }}>
              <CheckCircle size={44} />
            </div>
            <h1 className="login-screen-title">Password Updated</h1>
          </div>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 24, textAlign: 'center', lineHeight: 1.6 }}>
            Your password has been reset. You can now sign in with your new password.
          </p>
          <button className="btn-primary login-btn" onClick={() => navigate('/')}>
            <LogIn size={14} /> Go to Sign In
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="login-container">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-brand">
          <div className="login-brand-icon">
            <img src="/Images/kallix-icon-animated-transparent.gif" alt="Kallix" />
          </div>
          <h1 className="login-screen-title">Set New Password</h1>
        </div>

        {!token && (
          <div className="login-error">
            Invalid or missing reset token. Please request a new password reset link.
          </div>
        )}
        {error && <div className="login-error">{error}</div>}

        <div className="login-field">
          <label>New Password</label>
          <input type="password" value={newPassword}
                 onChange={e => setNewPassword(e.target.value)}
                 placeholder="New password" autoFocus autoComplete="new-password" />
        </div>

        <div className="login-field">
          <label>Confirm Password</label>
          <input type="password" value={confirmPassword}
                 onChange={e => setConfirm(e.target.value)}
                 placeholder="Confirm new password" autoComplete="new-password" />
        </div>

        <button type="submit" className="btn-primary login-btn"
                disabled={loading || !token}>
          {loading ? 'Saving...' : <><KeyRound size={14} /> Reset Password</>}
        </button>
      </form>
    </div>
  );
}
