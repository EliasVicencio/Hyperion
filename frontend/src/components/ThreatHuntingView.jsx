import React, { useEffect, useState } from 'react';
import { connectThreatStream, fetchThreatEvents } from '../services/threatHuntingApi';

export const ThreatHuntingView = () => {
  const [events, setEvents] = useState([]);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // Carga inicial de eventos históricos
    fetchThreatEvents()
      .then((data) => setEvents(data))
      .catch((err) => console.error(err));

    // Conexión al flujo en tiempo real
    const socket = connectThreatStream(
      (newEvent) => {
        setEvents((prevEvents) => [newEvent, ...prevEvents]);
      },
      () => setIsConnected(false)
    );

    setIsConnected(true);

    return () => {
      socket.close();
    };
  }, []);

  const getSeverityBadge = (severity) => {
    const colors = {
      CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/50',
      HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
      MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
      LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
    };
    return colors[severity] || colors.LOW;
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Hunting Live Monitor</h1>
          <p className="text-gray-400 text-sm">
            Ingesta en tiempo real desde Splunk & Microsoft Sentinel
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <span
            className={`h-3 w-3 rounded-full ${
              isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'
            }`}
          />
          <span className="text-sm font-medium text-gray-300">
            {isConnected ? 'STREAM ACTIVO' : 'DESCONECTADO'}
          </span>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-left text-sm text-gray-300">
          <thead className="bg-gray-800/50 text-gray-400 uppercase text-xs">
            <tr>
              <th className="px-4 py-3">SIEM</th>
              <th className="px-4 py-3">Regla / Regla de Alerta</th>
              <th className="px-4 py-3">Severidad</th>
              <th className="px-4 py-3">IP Origen</th>
              <th className="px-4 py-3">IP Destino</th>
              <th className="px-4 py-3">Timestamp</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {events.length === 0 ? (
              <tr>
                <td colSpan="6" className="text-center py-8 text-gray-500">
                  Esperando eventos en tiempo real...
                </td>
              </tr>
            ) : (
              events.map((event) => (
                <tr key={event.event_id} className="hover:bg-gray-800/30 transition-colors">
                  <td className="px-4 py-3 font-semibold text-white">{event.provider}</td>
                  <td className="px-4 py-3">{event.rule_name}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-1 text-xs rounded-full border ${getSeverityBadge(
                        event.severity
                      )}`}
                    >
                      {event.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{event.source_ip}</td>
                  <td className="px-4 py-3 font-mono text-xs">{event.destination_ip}</td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};