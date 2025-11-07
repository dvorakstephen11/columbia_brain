import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { useAuth } from '@/hooks/useAuth';

const UsernameSetupPage = () => {
  const { me, loading, pendingRegistration, completeUsername } = useAuth();
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (pendingRegistration) {
      setSuccess(false);
    }
  }, [pendingRegistration]);

  if (!loading && me) {
    return (
      <div className="auth-card">
        <h2 className="auth-card__title">Username already set</h2>
        <p className="auth-card__intro">You can go straight to the calendar.</p>
        <Link to="/" className="auth-form__submit auth-form__submit--link">
          Back to calendar
        </Link>
      </div>
    );
  }

  if (success) {
    return (
      <div className="auth-card">
        <h2 className="auth-card__title">Username saved</h2>
        <p className="auth-card__intro">All set. You can log in with your email and password now.</p>
        <Link to="/login" className="auth-form__submit auth-form__submit--link">
          Go to log in
        </Link>
        <p className="auth-card__footer">
          Need a different email?{' '}
          <Link to="/register" className="auth-link">
            Start over
          </Link>
        </p>
      </div>
    );
  }

  if (!pendingRegistration || pendingRegistration?.stage !== 'username') {
    return (
      <div className="auth-card">
        <h2 className="auth-card__title">You&apos;re almost there</h2>
        <p className="auth-card__intro">
          Finish registration by verifying your email first so we know it&apos;s really you.
        </p>
        <Link to="/verify" className="auth-form__submit auth-form__submit--link">
          Enter verification code
        </Link>
      </div>
    );
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      await completeUsername(username);
      setSuccess(true);
    } catch (err) {
      setError(err.message || 'Unable to save username');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-card">
      <h2 className="auth-card__title">Choose a username</h2>
      <p className="auth-card__intro">
        Usernames help friends find you. They must be 3–30 characters with letters, numbers, or underscores.
      </p>
      <form className="auth-form" onSubmit={handleSubmit}>
        <label className="auth-form__field">
          <span>Username</span>
          <input
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
            minLength={3}
            maxLength={30}
            autoComplete="username"
          />
        </label>
        {error ? (
          <p className="auth-form__message auth-form__message--error" role="alert">
            {error}
          </p>
        ) : null}
        <button type="submit" className="auth-form__submit" disabled={submitting}>
          {submitting ? 'Saving…' : 'Save username'}
        </button>
      </form>
      <div className="auth-card__footer auth-card__footer--stack">
        <p>
          Ready to sign in?{' '}
          <Link to="/login" className="auth-link">
            Log in
          </Link>
        </p>
        <p>
          Need a different email?{' '}
          <Link to="/register" className="auth-link">
            Start over
          </Link>
        </p>
      </div>
    </div>
  );
};

export default UsernameSetupPage;
