// Apunta a la URL real de tu API backend
const getBaseUrl = () => {
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL;
  }
  // Cambia esto por la URL correcta donde corre tu API (ej: Render, Railway, Fly.io, etc.)
  return 'https://hyperion-core.vercel.app'; 
};

const getWebSocketUrl = () => {
  const cleanBase = getBaseUrl().replace(/\/$/, '');
  const wsProtocol = cleanBase.startsWith('https') ? 'wss' : 'ws';
  const hostPath = cleanBase.replace(/^https?:\/\/(api\.)?/, '');
  return `${wsProtocol}://${hostPath}/threat-hunting/ws/live`;
};

export const connectThreatStream = (onEventReceived, onError) => {
  const wsUrl = getWebSocketUrl();
  let socket = null;

  try {
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      console.log('Stream de Threat Hunting conectado vía WebSocket');
    };

    socket.onmessage = (event) => {
      try {
        const parsedData = JSON.parse(event.data);
        onEventReceived(parsedData);
      } catch (err) {
        console.error('Error parseando evento de WebSocket:', err);
      }
    };

    socket.onerror = (error) => {
      console.warn('Conexión WebSocket fallida (Vercel no soporta WS nativo). Fallback a HTTP.');
      if (onError) onError(error);
    };

    socket.onclose = () => {
      console.log('Conexión WebSocket cerrada');
    };
  } catch (e) {
    console.warn('Error inicializando WebSocket:', e);
  }

  return socket;
};

export const fetchThreatEvents = async () => {
  const baseUrl = getBaseUrl().replace(/\/$/, '');
  const response = await fetch(`${baseUrl}/threat-hunting/events`);
  if (!response.ok) {
    throw new Error('Error al recuperar eventos de amenazas');
  }
  return await response.json();
};