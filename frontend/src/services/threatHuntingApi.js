import { BASE_URL } from "../api";

// Genera la URL del WebSocket adaptando http -> ws y https -> wss
const getWebSocketUrl = () => {
  const cleanBase = BASE_URL.replace(/\/$/, '');
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
  const response = await fetch(`${BASE_URL}/threat-hunting/events`);
  if (!response.ok) {
    throw new Error('Error al recuperar eventos de amenazas');
  }
  return await response.json();
};