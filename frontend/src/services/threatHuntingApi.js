import { fetchAPI } from '../api';

const getWebSocketUrl = () => {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${wsProtocol}://${window.location.host}/api/v1/threat-hunting/ws/live`;
};

export const fetchThreatEvents = async () => {
  return await fetchAPI('/threat-hunting/events');
};

export const connectThreatStream = (onEventReceived, onError) => {
  const wsUrl = getWebSocketUrl();
  let socket = null;
  let pollingInterval = null;

  // Respaldo vía HTTP Polling (cada 3 segundos) para plataformas Serverless
  const startHttpPolling = () => {
    console.log('Iniciando fallback de Threat Hunting vía HTTP Polling...');

    const poll = async () => {
      try {
        const events = await fetchThreatEvents();
        if (Array.isArray(events)) {
          events.forEach((event) => onEventReceived(event));
        }
      } catch (err) {
        console.error('Error en HTTP Polling:', err);
      }
    };

    poll(); // Ejecución inmediata
    pollingInterval = setInterval(poll, 3000);
  };

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
      console.warn('WebSocket no soportado en Vercel Serverless. Activando HTTP Polling.');
      if (onError) onError(error);
      if (!pollingInterval) startHttpPolling();
    };

    socket.onclose = () => {
      console.log('Conexión WebSocket cerrada');
    };
  } catch (e) {
    console.warn('Error al crear WebSocket. Activando HTTP Polling directamente.');
    startHttpPolling();
  }

  // Retorna objeto con método de limpieza seguro
  return {
    close: () => {
      if (socket) socket.close();
      if (pollingInterval) clearInterval(pollingInterval);
    },
  };
};