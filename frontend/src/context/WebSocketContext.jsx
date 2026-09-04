import React, { createContext, useContext, useEffect, useState } from 'react';
import { getToken } from '../api';

// 1. Creamos el contexto
const WebSocketContext = createContext(null);

// 2. Exportamos un hook para que sea facilísimo de usar en cualquier pantalla
export const useWebSocket = () => {
  return useContext(WebSocketContext);
};

// 3. Creamos el proveedor que envolverá tu app
export const WebSocketProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [mensajes, setMensajes] = useState([]);
  const [conectado, setConectado] = useState(false);

  useEffect(() => {
    const token = getToken();
    if (!token) return;

    // Ajusta esta URL si tu backend corre en otro puerto localmente (ej: ws://localhost:8000/ws)
    const wsUrl = `ws://localhost:8000/api/v1/ws?token=${token}`; 
    let ws = new WebSocket(wsUrl);

    const conectar = () => {
      ws.onopen = () => {
        console.log('🟢 WebSocket Central Conectado');
        setConectado(true);
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        // Guardamos los últimos 50 mensajes en memoria para no saturar
        setMensajes((prev) => [data, ...prev].slice(0, 50)); 
      };

      ws.onclose = () => {
        console.log('🔴 WebSocket Desconectado. Reconectando en 3s...');
        setConectado(false);
        setTimeout(() => {
          ws = new WebSocket(wsUrl);
          conectar();
        }, 3000);
      };

      ws.onerror = (err) => {
        console.error('⚠️ Error en WebSocket Central', err);
        ws.close();
      };
    };

    conectar();
    setSocket(ws);

    // Limpieza al cerrar sesión
    return () => {
      ws.close();
    };
  }, []);

  return (
    <WebSocketContext.Provider value={{ socket, mensajes, conectado }}>
      {children}
    </WebSocketContext.Provider>
  );
};