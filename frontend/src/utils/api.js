function readCookie(name) {
  const item = document.cookie.split('; ').find(row => row.startsWith(name + '='));
  return item ? decodeURIComponent(item.split('=')[1]) : null;
}

export async function api(path, { method = 'GET', data, headers } = {}) {
  const verb = method.toUpperCase();
  const isMutating = !['GET', 'HEAD', 'OPTIONS'].includes(verb);
  const baseHeaders = { 'Content-Type': 'application/json', ...(headers || {}) };

  if (isMutating) {
    const csrf = readCookie('csrf_token');
    if (csrf) {
      baseHeaders['X-CSRF-Token'] = csrf;
    }
  }

  const response = await fetch(path, {
    method: verb,
    headers: baseHeaders,
    credentials: 'include',
    body: data ? JSON.stringify(data) : undefined
  });

  if (!response.ok) {
    let message = 'Request failed';
    try {
      const payload = await response.json();
      message = payload.detail || message;
    } catch (err) {
      /* ignore JSON parse errors */
    }
    throw new Error(message);
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

export async function ensureCsrf() {
  try {
    await api('/auth/csrf');
  } catch (err) {
    console.warn('Failed to establish CSRF cookie', err);
  }
}
