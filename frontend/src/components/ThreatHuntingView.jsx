import React, { useState, useEffect } from 'react';
import { fetchThreatEvents, connectThreatStream } from '../services/threatHuntingApi';

export default function ThreatHuntingView() {
  const [events, setEvents] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let streamHandler = null;

    // Carga inicial de datos
    fetchThreatEvents()
      .then((data) => {
        if (Array.isArray(data)) {
          setEvents(data);
        }
      })
      .catch((err) => console.error('Error al cargar eventos iniciales:', err))
      .finally(() => setLoading(false));

    // Conexión en tiempo real con fallback automático
    streamHandler = connectThreatStream(
      (newEvent) => {
        setIsConnected(true);
        setEvents((prevEvents) => {
          // Evita eventos duplicados por ID
          const exists = prevEvents.some((e) => e.event_id === newEvent.event_id);
          if (exists) return prevEvents;
          return [newEvent, ...prevEvents];
        });
      },
      () => {
        // En caso de usar el fallback por HTTP polling
        setIsConnected(true);
      }
    );

    return () => {
      if (streamHandler && typeof streamHandler.close === 'function') {
        streamHandler.close();
      }
    };
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Hunting Live Monitor</h1>
          <p className="text-sm text-slate-400">
            Ingesta en tiempo real desde Splunk & Microsoft Sentinel
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`h-3 w-3 rounded-full ${
              isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'
            }`}
          />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            {isConnected ? 'EN VIVO' : 'DESCONECTADO'}
          </span>
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/50 shadow-xl backdrop-blur">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-950/80 text-xs uppercase text-slate-400">
            <tr>
              <th className="px-6 py-4">SIEM</th>
              <th className="px-6 py-4">REGLA / REGLA DE ALERTA</th>
              <th className="px-6 py-4">SEVERIDAD</th>
              <th className="px-6 py-4">IP ORIGEN</th>
              <th className="px-6 py-4">IP DESTINO</th>
              <th className="px-6 py-4">TIMESTAMP</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {loading ? (
              <tr>
                <td colSpan="6" className="px-6 py-8 text-center text-slate-500">
                  Cargando eventos de seguridad...
                </td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan="6" className="px-6 py-8 text-center text-slate-500">
                  Esperando eventos en tiempo real...
                </td>
              </tr>
            ) : (
              events.map((event) => (
                <tr key={event.event_id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-6 py-4 font-semibold text-slate-200">
                    {event.provider}
                  </td>
                  <td className="px-6 py-4 font-medium text-slate-100">
                    {event.rule_name}
                  </td>
                  <td className="px-6 py-4">
                    <span
                      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                        event.severity === 'CRITICAL' || event.severity === 'HIGH'
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                          : event.severity === 'MEDIUM'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      }`}
                    >
                      {event.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 font-mono text-xs text-slate-400">
                    {event.source_ip || '0.0.0.0'}
                  </td>
                  <td className="px-6 py-4 font-mono text-xs text-slate-400">
                    {event.destination_ip || '0.0.0.0'}
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-400">
                    {event.timestamp}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}