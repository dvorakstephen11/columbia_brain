import { useCallback, useEffect, useState } from 'react';

import { api, ensureCsrf } from '@/utils/api';

export function useAuth() {
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const data = await api('/auth/me');
      setMe(data);
    } catch (err) {
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    ensureCsrf().then(refresh);
  }, [refresh]);

  const register = useCallback(async (email, password) => {
    await ensureCsrf();
    await api('/auth/register', { method: 'POST', data: { email, password } });
  }, []);

  const login = useCallback(async (email, password) => {
    await ensureCsrf();
    await api('/auth/login', { method: 'POST', data: { email, password } });
    await refresh();
  }, [refresh]);

  const logout = useCallback(async () => {
    await ensureCsrf();
    await api('/auth/logout', { method: 'POST' });
    setMe(null);
  }, []);

  return { me, loading, register, login, logout, refresh };
}
