// URL base centralizada apuntando al backend activo en Vercel
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

  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
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
    console.error(`Error en petición API (${endpoint}):`, error);
    throw error;
  }
};

// --- MÉTODOS GENÉRICOS (Requeridos por tus componentes React) ---
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

// --- MÓDULO DE TICKETS ---
export const getTickets = async () => {
  return fetchAPI('/tickets');
};

export const createTicket = async (ticketData) => {
  return fetchAPI('/tickets', {
    method: 'POST',
    body: JSON.stringify(ticketData),
  });
};