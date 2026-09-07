import { createClient } from '@supabase/supabase-js';

// --- INSTANCIA ÚNICA DE SUPABASE (EVITA RE-CREACIÓN DE CLIENTES) ---
const SUPABASE_URL = 'https://tyunqthoinamdlyhgmuq.supabase.co';
const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const BASE_URL = 'https://hyperion-core.vercel.app';

export const getToken = () => localStorage.getItem('hyperion_token');

export const setToken = (token) => {
  if (token) {
    localStorage.setItem('hyperion_token', token);
  } else {
    localStorage.removeItem('hyperion_token');
  }
};

export const fetchAPI = async (endpoint, options = {}) => {
  const token = getToken();

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  // Sanitización de ruta: asegura prefijos limpios
  let path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  if (path.startsWith('/api/v1')) {
    path = path.replace('/api/v1', '');
  }

  const url = `${BASE_URL}${path}`;

  try {
    const response = await fetch(url, { ...options, headers });

    const contentType = response.headers.get('content-type');
    const isJson = contentType && contentType.includes('application/json');

    if (!response.ok) {
      const errorData = isJson ? await response.json().catch(() => ({})) : {};
      const error = new Error(errorData.detail || errorData.message || `Error HTTP: ${response.status}`);
      error.status = response.status;
      throw error;
    }

    if (isJson) {
      return await response.json();
    }

    return await response.text();
  } catch (error) {
    console.error(`Error en petición API (${path}):`, error);
    throw error;
  }
};

// Métodos HTTP Genéricos
export const apiGet = async (endpoint) => fetchAPI(endpoint, { method: 'GET' });
export const apiPost = async (endpoint, data) => fetchAPI(endpoint, { method: 'POST', body: JSON.stringify(data) });
export const apiPut = async (endpoint, data) => fetchAPI(endpoint, { method: 'PUT', body: JSON.stringify(data) });
export const apiPatch = async (endpoint, data) => fetchAPI(endpoint, { method: 'PATCH', body: JSON.stringify(data) });
export const apiDelete = async (endpoint) => fetchAPI(endpoint, { method: 'DELETE' });

// --- ENDPOINTS ESPECÍFICOS DEL SISTEMA ---
// Nota: Se agrega '/' al final para garantizar compatibilidad con FastAPI en Vercel
export const getTickets = async () => fetchAPI('/tickets/');
export const createTicket = async (ticketData) => fetchAPI('/tickets/', { method: 'POST', body: JSON.stringify(ticketData) });
export const updateTicket = async (ticketId, ticketData) => fetchAPI(`/tickets/${ticketId}/`, { method: 'PATCH', body: JSON.stringify(ticketData) });
export const deleteTicket = async (ticketId) => fetchAPI(`/tickets/${ticketId}/`, { method: 'DELETE' });

export const getLogs = async () => fetchAPI('/logs/');
export const checkHealth = async () => fetchAPI('/health/');