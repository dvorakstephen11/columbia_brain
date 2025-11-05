import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const VerifyPage = () => {
  const { me, loading, pendingRegistration, verifyCode } = useAuth();
  const navigate = useNavigate();
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (pendingRegistration?.mockCode && !code) {
      setCode(pendingRegistration.mockCode);
    }
  }, [pendingRegistration, code]);

  useEffect(() => {
    setError('');
  }, [code]);

  useEffect(() => {
    if (pendingRegistration?.stage === 'username') {
      navigate('/username-setup', { replace: true });
    }
  }, [pendingRegistration, navigate]);

  if (!loading && me) {
    return (
      <div className="auth-card">
        <h2 className="auth-card__title">Already verified</h2>
        <p className="auth-card__intro">Your account is active. You can head back to the calendar.</p>
        <Link to="/" className="auth-form__submit--link">
          Back to calendar
        </Link>
      </div>
    );
  }

  if (!pendingRegistration) {
    return (
      <div className="auth-card">
        <h2 className="auth-card__title">Need an account?</h2>
        <p className="auth-card__intro">
          Start by registering with your email and password so we know where to send your verification code.
        </p>
        <Link to="/register" className="auth-form__submit--link">
          Register now
        </Link>
      </div>
    );
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      const result = await verifyCode(code);
      if (result.username_required) {
        navigate('/username-setup', { replace: true });
      } else {
        navigate('/login', { replace: true });
      }
    } catch (err) {
      setError(err.message || 'Verification failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-card">
      <h2 className="auth-card__title">Check your email</h2>
      <p className="auth-card__intro">
        Enter the 6-digit code we sent to <strong>{pendingRegistration.email}</strong>.
      </p>
      <form className="auth-form" onSubmit={handleSubmit}>
        <label className="auth-form__field">
          <span>Verification code</span>
          <input
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            value={code}
            onChange={(event) => setCode(event.target.value)}
            required
          />
        </label>
        {error ? (
          <p className="auth-form__message auth-form__message--error" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="auth-form__submit" disabled={submitting}>
          {submitting ? 'Verifying…' : 'Verify'}
        </button>
      </form>
      <p className="auth-card__footer">
        Didn&apos;t get an email?{' '}
        <Link to="/register" className="auth-link">
          Try registering again
        </Link>
      </p>
    </div>
  );
};

export default VerifyPage;
