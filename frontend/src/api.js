// URL Base fija apuntando al backend activo en Vercel
const BASE_URL = 'https://hyperion-core.vercel.app/api/v1';

/**
 * Obtener el token de autenticación desde el almacenamiento local
 */
export const getToken = () => {
  return localStorage.getItem('hyperion_token');
};

/**
 * Cliente centralizado para peticiones HTTP
 */
export const fetchAPI = async (endpoint, options = {}) => {
  const token = getToken();
  
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...options.headers,
  };

  // Previene dobles barras diagonales en la construcción de la URL
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

/**
 * Endpoints del módulo de Tickets
 */
export const getTickets = async () => {
  return fetchAPI('/tickets');
};

export const createTicket = async (ticketData) => {
  return fetchAPI('/tickets', {
    method: 'POST',
    body: JSON.stringify(ticketData),
  });
};