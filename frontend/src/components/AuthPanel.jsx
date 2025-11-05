import React, { useState } from 'react';

import { useAuth } from '@/hooks/useAuth';

const AuthPanel = () => {
  const { me, loading, register, login, logout, verifyCode } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState('login');
  const [message, setMessage] = useState('');
  const [devVerificationCode, setDevVerificationCode] = useState(null);
  const [verificationEntry, setVerificationEntry] = useState('');
  const [verificationMessage, setVerificationMessage] = useState('');

  if (loading) {
    return null;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setMessage('');
    setVerificationMessage('');
    try {
      if (mode === 'register') {
        const result = await register(email, password);
        const code = result?.verification_code ?? '';
        setDevVerificationCode(code);
        setVerificationEntry('');
        setMessage('Registration received. Check your email for a verification code (mock).');
      } else {
        await login(email, password);
        setDevVerificationCode(null);
        setVerificationEntry('');
      }
    } catch (err) {
      setMessage(err.message || 'Something went wrong.');
      setDevVerificationCode(null);
    }
  }

  async function handleVerify() {
    setVerificationMessage('');
    const code = verificationEntry.trim();
    if (!code) {
      setVerificationMessage('Enter the verification code shown above.');
      return;
    }
    try {
      await verifyCode(code);
      setMessage('Verification succeeded. You can now log in.');
      setVerificationMessage('');
      setDevVerificationCode(null);
    } catch (err) {
      setVerificationMessage(err.message || 'Verification failed.');
    }
  }

  function handleModeChange(nextMode) {
    setMode(nextMode);
    setMessage('');
    setVerificationMessage('');
    if (nextMode !== 'register') {
      setDevVerificationCode(null);
      setVerificationEntry('');
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
      <select value={mode} onChange={event => handleModeChange(event.target.value)}>
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
          {devVerificationCode ? (
            <span style={{ color: '#ffffff', marginLeft: 4 }} aria-hidden="true">
              {devVerificationCode}
            </span>
          ) : null}
        </span>
      )}
      {mode === 'register' && devVerificationCode ? (
        <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span>Verification code</span>
            <input
              type="text"
              value={verificationEntry}
              onChange={event => setVerificationEntry(event.target.value)}
              placeholder="Paste code"
            />
          </label>
          <button type="button" onClick={handleVerify}>
            Verify
          </button>
          {verificationMessage && (
            <span aria-live="polite" style={{ marginLeft: 8 }}>
              {verificationMessage}
            </span>
          )}
        </span>
      ) : null}
    </form>
  );
};

export default AuthPanel;
