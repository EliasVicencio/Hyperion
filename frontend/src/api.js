const API_BASE = import.meta.env.VITE_API_URL || 'https://tyunqthoinamdlyhgmuq.supabase.co';

export function getToken() {
  return localStorage.getItem('hyperion_token');
}

export function setToken(token) {
  if (token) {
    localStorage.setItem('hyperion_token', token);
  } else {
    localStorage.removeItem('hyperion_token');
  }
}

export async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { ...options.headers };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (!headers['Content-Type'] && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  // Asegura que no se dupliquen las barras en la ruta
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  const res = await fetch(`${API_BASE}${cleanPath}`, { ...options, headers });

  if (res.status === 401) {
    setToken(null);
    localStorage.removeItem('hyperion_auth');
    window.location.href = '/';
    throw new Error('Sesión expirada');
  }

  return res;
}

export function apiGet(path) {
  return apiFetch(path);
}

export function apiPost(path, body) {
  return apiFetch(path, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export function apiPatch(path, body) {
  return apiFetch(path, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export function apiDelete(path) {
  return apiFetch(path, { method: 'DELETE' });
}