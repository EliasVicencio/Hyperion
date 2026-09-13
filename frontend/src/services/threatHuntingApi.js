const getBaseUrl = () => {
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL;
  }
  return 'https://hyperion-core.vercel.app/api/v1';
};

const getWebSocketUrl = () => {
  const cleanBase = getBaseUrl().replace(/\/$/, '');
  const wsProtocol = cleanBase.startsWith('https') ? 'wss' : 'ws';
  const hostPath = cleanBase.replace(/^https?:\/\//, '');
  return `${wsProtocol}://${hostPath}/threat-hunting/ws/live`;
};

export const connectThreatStream = (onEventReceived, onError) => {
  const wsUrl = getWebSocketUrl();
  const socket = new WebSocket(wsUrl);

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
    console.error('Error en conexión WebSocket:', error);
    if (onError) onError(error);
  };

  socket.onclose = () => {
    console.log('Conexión WebSocket cerrada');
  };

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