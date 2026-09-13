import { fetchAPI } from '../api';

const getWebSocketUrl = () => {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${wsProtocol}://${window.location.host}/api/v1/threat-hunting/ws/live`;
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
      console.warn('Conexión WebSocket no disponible en Vercel Serverless. Usando HTTP.');
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
  // fetchAPI agrega automáticamente el prefijo /api/v1 y los headers necesarios
  return await fetchAPI('/threat-hunting/events');
};