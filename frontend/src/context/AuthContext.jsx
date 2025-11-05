import React, { createContext, useCallback, useEffect, useMemo, useState } from 'react';

import { api, ensureCsrf } from '@/utils/api';

const STORAGE_KEY = 'pending-registration';

function readStoredPending() {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (error) {
    console.warn('Failed to parse stored registration state', error);
    return null;
  }
}

function persistPending(pending) {
  if (typeof window === 'undefined') {
    return;
  }
  try {
    if (pending) {
      window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(pending));
    } else {
      window.sessionStorage.removeItem(STORAGE_KEY);
    }
  } catch (error) {
    console.warn('Failed to persist registration state', error);
  }
}

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);
  const [pendingRegistration, setPendingRegistration] = useState(() => readStoredPending());

  useEffect(() => {
    persistPending(pendingRegistration);
  }, [pendingRegistration]);

  const refresh = useCallback(async () => {
    try {
      const data = await api('/auth/me');
      setMe(data);
    } catch (error) {
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function boot() {
      try {
        await ensureCsrf();
        if (!cancelled) {
          await refresh();
        }
      } catch (error) {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    boot();
    return () => {
      cancelled = true;
    };
  }, [refresh]);

  const register = useCallback(
    async (email, password) => {
      const normalizedEmail = email.trim().toLowerCase();
      await ensureCsrf();
      const data = await api('/auth/register', {
        method: 'POST',
        data: { email: normalizedEmail, password }
      });
      const next = {
        email: normalizedEmail,
        stage: 'verify',
        registrationToken: data.registration_token,
        mockCode: data.mock_verification_code ?? null
      };
      setPendingRegistration(next);
      return next;
    },
    []
  );

  const verifyCode = useCallback(
    async (code, overrides = {}) => {
      const token = overrides.registrationToken ?? pendingRegistration?.registrationToken ?? null;
      const email = overrides.email ?? pendingRegistration?.email ?? null;

      if (!token && !email) {
        throw new Error('Account details required to verify code.');
      }

      const payload = { code };
      if (token) payload.registration_token = token;
      if (email) payload.email = email;

      const data = await api('/auth/verify-code', { method: 'POST', data: payload });

      if (data.username_required) {
        if (!data.registration_token) {
          throw new Error('Missing registration token for username setup.');
        }
        setPendingRegistration({
          email,
          stage: 'username',
          registrationToken: data.registration_token,
          mockCode: null
        });
      } else {
        setPendingRegistration(null);
      }

      return data;
    },
    [pendingRegistration]
  );

  const completeUsername = useCallback(
    async (username, overrides = {}) => {
      const token = overrides.registrationToken ?? pendingRegistration?.registrationToken ?? null;
      if (!token) {
        throw new Error('Registration token required to complete username.');
      }
      const data = await api('/auth/username', {
        method: 'POST',
        data: { username, registration_token: token }
      });
      setPendingRegistration(null);
      return data;
    },
    [pendingRegistration]
  );

  const login = useCallback(
    async (email, password) => {
      await ensureCsrf();
      await api('/auth/login', { method: 'POST', data: { email, password } });
      await refresh();
    },
    [refresh]
  );

  const logout = useCallback(async () => {
    await ensureCsrf();
    await api('/auth/logout', { method: 'POST' });
    setMe(null);
  }, []);

  const clearPendingRegistration = useCallback(() => {
    setPendingRegistration(null);
  }, []);

  const value = useMemo(
    () => ({
      me,
      loading,
      pendingRegistration,
      register,
      verifyCode,
      completeUsername,
      login,
      logout,
      refresh,
      clearPendingRegistration
    }),
    [
      clearPendingRegistration,
      completeUsername,
      loading,
      login,
      logout,
      me,
      pendingRegistration,
      refresh,
      register,
      verifyCode
    ]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
