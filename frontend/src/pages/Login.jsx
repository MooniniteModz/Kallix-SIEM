import { useState } from 'react';
import { LogIn } from 'lucide-react';
import FirewatchLogo from '../components/FirewatchLogo';
import { api } from '../api';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.login(username, password);
      localStorage.setItem('outpost_token', data.token);
      onLogin(data);
    } catch (err) {
      setError(err.message === 'API error: 401' ? 'Invalid username or password' : err.message);
    }
    setLoading(false);
  }

  return (
    <div className="login-container">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-logo">
          <div className="logo-icon"><FirewatchLogo size={24} /></div>
          <div>
            <h1>Firewatch</h1>
            <span>SIEM Platform</span>
          </div>
        </div>

        {error && <div className="login-error">{error}</div>}

        <div className="login-field">
          <label>Username</label>
          <input
            type="text"
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="admin"
            autoFocus
            autoComplete="username"
          />
        </div>

        <div className="login-field">
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Enter password"
            autoComplete="current-password"
          />
        </div>

        <button type="submit" className="btn-primary login-btn" disabled={loading}>
          {loading ? 'Signing in...' : <><LogIn size={14} /> Sign In</>}
        </button>
      </form>
    </div>
  );
}
