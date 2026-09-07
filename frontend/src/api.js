import { createClient } from '@supabase/supabase-js';

// Configuración de Supabase Client (si lo necesitas de manera global)
const SUPABASE_URL = 'https://YOUR_SUPABASE_PROJECT_ID.supabase.co';
const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';
export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// URL base centralizada
const BASE_URL = 'https://hyperion-core.vercel.app/api/v1';

// --- GESTIÓN DE TOKENS ---
export const getToken = () => {
  return localStorage.getItem('hyperion_token');
};

export const setToken = (token) => {
  if (token) {
    localStorage.setItem('hyperion_token', token);
  } else {
    localStorage.removeItem('hyperion_token');
  }
};

// --- CLIENTE HTTP BASE ---
export const fetchAPI = async (endpoint, options = {}) => {
  const token = getToken();

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...options.headers,
  };

  // Prevenir '/api/v1/api/v1/...' cuando el componente envía el prefijo
  let cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  if (cleanEndpoint.startsWith('/api/v1')) {
    cleanEndpoint = cleanEndpoint.replace('/api/v1', '');
  }

  const url = `${BASE_URL}${cleanEndpoint}`;

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `Error HTTP: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error(`Error en petición API (${cleanEndpoint}):`, error);
    throw error;
  }
};

// --- MÉTODOS HTTP GENÉRICOS ---
export const apiGet = async (endpoint) => {
  return fetchAPI(endpoint, { method: 'GET' });
};

export const apiPost = async (endpoint, data) => {
  return fetchAPI(endpoint, {
    method: 'POST',
    body: JSON.stringify(data),
  });
};

export const apiPut = async (endpoint, data) => {
  return fetchAPI(endpoint, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
};

export const apiPatch = async (endpoint, data) => {
  return fetchAPI(endpoint, {
    method: 'PATCH',
    body: JSON.stringify(data),
  });
};

export const apiDelete = async (endpoint) => {
  return fetchAPI(endpoint, { method: 'DELETE' });
};

// --- MÓDULOS ESPECÍFICOS ---
export const getTickets = async () => {
  return fetchAPI('/tickets');
};

export const createTicket = async (ticketData) => {
  return fetchAPI('/tickets', {
    method: 'POST',
    body: JSON.stringify(ticketData),
  });
};

export const updateTicket = async (ticketId, ticketData) => {
  return fetchAPI(`/tickets/${ticketId}`, {
    method: 'PATCH',
    body: JSON.stringify(ticketData),
  });
};

export const deleteTicket = async (ticketId) => {
  return fetchAPI(`/tickets/${ticketId}`, {
    method: 'DELETE',
  });
};

export const getLogs = async () => {
  return fetchAPI('/logs');
};

export const checkHealth = async () => {
  return fetchAPI('/health');
};