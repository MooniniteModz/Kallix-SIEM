import { useState } from 'react';
import { LogIn, Mail, ArrowLeft, CheckCircle, Shield, KeyRound, Lock } from 'lucide-react';
import KallixLogo from '../components/KallixLogo';
import { api } from '../api';

export default function Login({ onLogin }) {
  const [view, setView]               = useState('login');
  const [mfaToken, setMfaToken]       = useState('');
  const [changeToken, setChangeToken] = useState('');

  function handlePasswordOk(data) {
    if (data.password_change_required) {
      setChangeToken(data.change_token);
      setView('set_password');
    } else if (data.mfa_required) {
      setMfaToken(data.mfa_token);
      setView('mfa');
    } else {
      onLogin(data);
    }
  }

  return (
    <div className="login-container">
      {view === 'login'        && <LoginForm       onLogin={handlePasswordOk} onForgot={() => setView('forgot')} />}
      {view === 'set_password' && <SetPasswordForm changeToken={changeToken} onLogin={onLogin} />}
      {view === 'mfa'          && <MfaForm         mfaToken={mfaToken} onLogin={onLogin} onBack={() => setView('login')} />}
      {view === 'forgot'       && <ForgotForm      onBack={() => setView('login')} onSent={() => setView('forgot_sent')} />}
      {view === 'forgot_sent'  && <ForgotSent      onBack={() => setView('login')} />}
    </div>
  );
}

function LoginForm({ onLogin, onForgot }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.login(username, password);
      onLogin(data);
    } catch (err) {
      setError(err.message === 'API error: 401' ? 'Invalid username or password' : err.message);
    }
    setLoading(false);
  }

  return (
    <form className="login-card" onSubmit={handleSubmit}>
      <div className="login-brand">
        <div className="login-brand-icon">
          <img src="/Images/kallix-icon-animated-transparent.gif" alt="Kallix" />
        </div>
        <h1 className="login-brand-name">Kallix</h1>
      </div>

      {error && <div className="login-error">{error}</div>}

      <div className="login-field">
        <label>Email</label>
        <input type="email" value={username} onChange={e => setUsername(e.target.value)}
               placeholder="you@example.com" autoFocus autoComplete="email" />
      </div>

      <div className="login-field">
        <label>Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)}
               placeholder="Enter password" autoComplete="current-password" />
      </div>

      <button type="submit" className="btn-primary login-btn" disabled={loading}>
        {loading ? 'Signing in...' : <><LogIn size={14} /> Sign In</>}
      </button>

      <button type="button" className="login-forgot-link" onClick={onForgot}>
        Forgot your password?
      </button>
    </form>
  );
}

function SetPasswordForm({ changeToken, onLogin }) {
  const [password, setPassword]   = useState('');
  const [confirm, setConfirm]     = useState('');
  const [error, setError]         = useState('');
  const [loading, setLoading]     = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    if (password !== confirm) { setError('Passwords do not match.'); return; }
    setLoading(true);
    try {
      const data = await api.setPassword(changeToken, password);
      onLogin(data);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  }

  return (
    <form className="login-card" onSubmit={handleSubmit}>
      <div className="login-brand">
        <div className="login-brand-icon" style={{ color: 'var(--accent)' }}>
          <Lock size={44} />
        </div>
        <h1 className="login-screen-title">Set Your Password</h1>
      </div>

      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, textAlign: 'center', lineHeight: 1.6 }}>
        Choose a strong password — at least 12 characters with uppercase, lowercase, a number, and a special character.
      </p>

      {error && <div className="login-error">{error}</div>}

      <div className="login-field">
        <label>New Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)}
               placeholder="New password" autoFocus autoComplete="new-password" />
      </div>

      <div className="login-field">
        <label>Confirm Password</label>
        <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)}
               placeholder="Repeat password" autoComplete="new-password" />
      </div>

      <button type="submit" className="btn-primary login-btn" disabled={loading}>
        {loading ? 'Saving...' : <><Lock size={14} /> Set Password</>}
      </button>
    </form>
  );
}

function MfaForm({ mfaToken, onLogin, onBack }) {
  const [code, setCode]             = useState('');
  const [backupCode, setBackupCode] = useState('');
  const [useBackup, setUseBackup]   = useState(false);
  const [error, setError]           = useState('');
  const [loading, setLoading]       = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.mfaChallenge(
        mfaToken,
        useBackup ? '' : code.replace(/\s/g, ''),
        useBackup ? backupCode.trim() : ''
      );
      onLogin(data);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  }

  return (
    <form className="login-card" onSubmit={handleSubmit}>
      <div className="login-brand">
        <div className="login-brand-icon" style={{ color: 'var(--accent)' }}>
          <Shield size={44} />
        </div>
        <h1 className="login-screen-title">Two-Factor Authentication</h1>
      </div>

      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, textAlign: 'center', lineHeight: 1.6 }}>
        {useBackup
          ? 'Enter one of your 8-character backup codes.'
          : 'Enter the 6-digit code from your authenticator app.'}
      </p>

      {error && <div className="login-error">{error}</div>}

      {!useBackup ? (
        <div className="login-field">
          <label>Authenticator Code</label>
          <input
            type="text" inputMode="numeric" pattern="[0-9 ]*"
            maxLength={7} value={code}
            onChange={e => setCode(e.target.value.replace(/[^0-9]/g, ''))}
            placeholder="000000" autoFocus autoComplete="one-time-code"
            style={{ letterSpacing: '0.25em', fontSize: 22, textAlign: 'center' }}
          />
        </div>
      ) : (
        <div className="login-field">
          <label>Backup Code</label>
          <input
            type="text" value={backupCode}
            onChange={e => setBackupCode(e.target.value.toUpperCase())}
            placeholder="XXXX-XXXX" autoFocus
            style={{ letterSpacing: '0.1em', fontFamily: 'var(--mono)', textAlign: 'center' }}
          />
        </div>
      )}

      <button type="submit" className="btn-primary login-btn" disabled={loading}>
        {loading ? 'Verifying...' : <><Shield size={14} /> Verify</>}
      </button>

      <button type="button" className="login-forgot-link" onClick={() => { setUseBackup(b => !b); setError(''); }}>
        <KeyRound size={13} style={{ verticalAlign: 'middle', marginRight: 4 }} />
        {useBackup ? 'Use authenticator app instead' : 'Use a backup code instead'}
      </button>

      <button type="button" className="login-forgot-link" onClick={onBack} style={{ marginTop: 4 }}>
        <ArrowLeft size={13} style={{ verticalAlign: 'middle', marginRight: 4 }} />
        Back to sign in
      </button>
    </form>
  );
}

function ForgotForm({ onBack, onSent }) {
  const [email, setEmail]     = useState('');
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    if (!email.trim()) { setError('Please enter your email address.'); return; }
    setLoading(true);
    try {
      await api.forgotPassword(email.trim());
      onSent();
    } catch (err) {
      setError(err.message || 'Something went wrong. Please try again.');
    }
    setLoading(false);
  }

  return (
    <form className="login-card" onSubmit={handleSubmit}>
      <div className="login-brand">
        <div className="login-brand-icon">
          <img src="/Images/kallix-icon-animated-transparent.gif" alt="Kallix" />
        </div>
        <h1 className="login-screen-title">Reset Password</h1>
      </div>

      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, textAlign: 'center' }}>
        Enter your account email and we'll send you a reset link.
      </p>

      {error && <div className="login-error">{error}</div>}

      <div className="login-field">
        <label>Email Address</label>
        <input type="email" value={email} onChange={e => setEmail(e.target.value)}
               placeholder="you@company.com" autoFocus autoComplete="email" />
      </div>

      <button type="submit" className="btn-primary login-btn" disabled={loading}>
        {loading ? 'Sending...' : <><Mail size={14} /> Send Reset Link</>}
      </button>

      <button type="button" className="login-forgot-link" onClick={onBack}>
        <ArrowLeft size={13} style={{ verticalAlign: 'middle', marginRight: 4 }} />
        Back to sign in
      </button>
    </form>
  );
}

function ForgotSent({ onBack }) {
  return (
    <div className="login-card">
      <div className="login-brand">
        <div className="login-brand-icon" style={{ color: 'var(--green)' }}>
          <CheckCircle size={44} />
        </div>
        <h1 className="login-screen-title">Check Your Email</h1>
      </div>

      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 24, textAlign: 'center', lineHeight: 1.6 }}>
        If that email is registered, a password reset link has been sent.
        The link expires in 1 hour.
      </p>

      <button type="button" className="btn-primary login-btn" onClick={onBack}>
        <LogIn size={14} /> Back to Sign In
      </button>
    </div>
  );
}
