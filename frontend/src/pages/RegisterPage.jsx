import React, { useEffect, useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const RegisterPage = () => {
  const { me, loading, register, pendingRegistration } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (pendingRegistration?.stage === 'verify') {
      return;
    }
    if (pendingRegistration?.stage === 'username') {
      navigate('/username-setup', { replace: true });
    }
  }, [pendingRegistration, navigate]);

  useEffect(() => {
    setError('');
  }, [email, password]);

  if (!loading && me) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      await register(email, password);
      navigate('/verify', { replace: false });
    } catch (err) {
      setError(err.message || 'Unable to register');
    } finally {
      setSubmitting(false);
    }
  };

  const mockCode = pendingRegistration?.mockCode ?? null;

  return (
    <div className="auth-card">
      <h2 className="auth-card__title">Create account</h2>
      <p className="auth-card__intro">
        Start by entering your email and a password. We will send a verification code to continue.
      </p>
      <form className="auth-form" onSubmit={handleSubmit}>
        <label className="auth-form__field">
          <span>Email</span>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
            autoComplete="email"
          />
        </label>
        <label className="auth-form__field">
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
            autoComplete="new-password"
          />
        </label>
        {error ? (
          <p className="auth-form__message auth-form__message--error" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="auth-form__submit" disabled={submitting}>
          {submitting ? 'Submitting…' : 'Register'}
        </button>
      </form>
      <p className="auth-card__footer">
        Already registered?{' '}
        <Link to="/login" className="auth-link">
          Log in
        </Link>
      </p>
      {mockCode ? (
        <p className="auth-card__mock-code" aria-live="polite">
          Dev verification code: <span>{mockCode}</span>
        </p>
      ) : null}
    </div>
  );
};

export default RegisterPage;
