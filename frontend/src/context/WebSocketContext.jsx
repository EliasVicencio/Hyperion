import React, { createContext, useContext, useEffect, useState } from 'react';
import { supabase } from '../supabaseClient';

const WebSocketContext = createContext(null);

export const useWebSocket = () => {
  return useContext(WebSocketContext);
};

export const WebSocketProvider = ({ children }) => {
  const [mensajes, setMensajes] = useState([]);
  const [conectado, setConectado] = useState(false);

  useEffect(() => {
    // Suscripción al canal central de eventos en Supabase
    const channel = supabase.channel('hyperion-events');

    channel
      .on('broadcast', { event: 'telemetry' }, (payload) => {
        // Al recibir un evento, guardamos los últimos 50 mensajes
        setMensajes((prev) => [payload.payload, ...prev].slice(0, 50));
      })
      .subscribe((status) => {
        if (status === 'SUBSCRIBED') {
          console.log('🟢 Supabase Realtime Conectado');
          setConectado(true);
        } else {
          setConectado(false);
        }
      });

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  return (
    <WebSocketContext.Provider value={{ socket: supabase, mensajes, conectado }}>
      {children}
    </WebSocketContext.Provider>
  );
};