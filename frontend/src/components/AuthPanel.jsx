import React, { useState } from 'react';

import { useAuth } from '@/hooks/useAuth';

const AuthPanel = () => {
  const { me, loading, register, login, logout } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState('login');
  const [message, setMessage] = useState('');

  if (loading) {
    return null;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setMessage('');
    try {
      if (mode === 'register') {
        await register(email, password);
        setMessage('Registration received. Check your email for a verification link (mock).');
      } else {
        await login(email, password);
      }
    } catch (err) {
      setMessage(err.message || 'Something went wrong.');
    }
  }

  if (me) {
    return (
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <span>
          Signed in as <strong>{me.email}</strong>
          {me.is_email_verified ? '' : ' (unverified)'}
        </span>
        <button type="button" onClick={() => logout()}>
          Log out
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
      <select value={mode} onChange={event => setMode(event.target.value)}>
        <option value="login">Log in</option>
        <option value="register">Register</option>
      </select>
      <input
        type="email"
        required
        placeholder="email"
        value={email}
        onChange={event => setEmail(event.target.value)}
      />
      <input
        type="password"
        required
        placeholder="password"
        value={password}
        onChange={event => setPassword(event.target.value)}
      />
      <button type="submit">{mode === 'register' ? 'Register' : 'Log in'}</button>
      {message && (
        <span aria-live="polite" style={{ marginLeft: 8 }}>
          {message}
        </span>
      )}
    </form>
  );
};

export default AuthPanel;
