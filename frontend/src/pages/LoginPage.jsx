import React, { useEffect, useState } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const LoginPage = () => {
  const { me, loading, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const destination = location.state?.from ?? '/';

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
      await login(email, password);
      navigate(destination, { replace: true });
    } catch (err) {
      setError(err.message || 'Unable to log in');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-card">
      <h2 className="auth-card__title">Log in</h2>
      <p className="auth-card__intro">Enter your credentials to access the calendar.</p>
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
            autoComplete="current-password"
          />
        </label>
        {error ? (
          <p className="auth-form__message auth-form__message--error" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="auth-form__submit" disabled={submitting}>
          {submitting ? 'Signing in…' : 'Log in'}
        </button>
      </form>
      <p className="auth-card__footer">
        No account yet?{' '}
        <Link to="/register" className="auth-link">
          Sign up
        </Link>
      </p>
    </div>
  );
};

export default LoginPage;
