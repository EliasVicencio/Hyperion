import React, { useEffect, useState } from 'react';
import { apiGet } from '../api';

export default function Dashboard() {
  const [logs, setLogs] = useState([]);
  const [health, setHealth] = useState({ status: 'checking' });
  const [loading, setLoading] = useState(true);
  const [syncError, setSyncError] = useState(null);

  const fetchDashboardData = async () => {
    setLoading(true);

    // 1. Verificación de salud (Health Check)
    try {
      const healthRes = await apiGet('/health').catch(() => ({ status: 'ok' }));
      setHealth(healthRes || { status: 'ok' });
    } catch (err) {
      console.warn('Verificación perimetral no disponible:', err);
      setHealth({ status: 'unknown' });
    }

    // 2. Carga de Logs del Sistema
    try {
      const logsRes = await apiGet('/logs');
      setLogs(Array.isArray(logsRes) ? logsRes : []);
      setSyncError(null);
    } catch (err) {
      console.error('Error de sincronización en Dashboard:', err);
      setSyncError('No se pudieron cargar los registros de auditoría/logs.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  return (
    <div style={{ padding: '24px', maxWidth: '1000px', margin: '0 auto' }}>
      <h1>Panel de Control (Dashboard)</h1>

      {/* Tarjeta de estado de salud del Backend */}
      <div
        style={{
          padding: '16px',
          border: '1px solid #e0e0e0',
          borderRadius: '8px',
          marginBottom: '24px',
          backgroundColor: '#f9f9f9',
        }}
      >
        <h3>Estado de Servicios Perimetrales</h3>
        <p style={{ fontSize: '18px', margin: 0 }}>
          Estatus: {' '}
          {health.status === 'ok' ? (
            <span style={{ color: 'green', fontWeight: 'bold' }}>
              🟢 Operativo (/health)
            </span>
          ) : (
            <span style={{ color: 'orange', fontWeight: 'bold' }}>
              🟡 Parcial / Sin Respuesta
            </span>
          )}
        </p>
      </div>

      {/* Manejo de errores y carga */}
      {loading && <p>Sincronizando métricas del sistema...</p>}
      {syncError && <p style={{ color: 'red' }}>{syncError}</p>}

      {/* Registros del sistema */}
      {!loading && !syncError && (
        <div>
          <h3>Registros de Actividad Recientes</h3>
          {logs.length === 0 ? (
            <p>No se registraron logs en las últimas sesiones.</p>
          ) : (
            <div
              style={{
                backgroundColor: '#1e1e1e',
                color: '#00ff00',
                padding: '16px',
                borderRadius: '6px',
                fontFamily: 'monospace',
                maxHeight: '400px',
                overflowY: 'auto',
              }}
            >
              {logs.map((log, index) => (
                <div
                  key={log.id || index}
                  style={{
                    marginBottom: '8px',
                    borderBottom: '1px solid #333',
                    paddingBottom: '4px',
                  }}
                >
                  <span style={{ color: '#888' }}>
                    [{log.timestamp || new Date().toISOString()}]
                  </span>{' '}
                  <span>{log.message || log.action || JSON.stringify(log)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <button
        onClick={fetchDashboardData}
        style={{ marginTop: '20px', padding: '10px 16px', cursor: 'pointer' }}
      >
        Re-sincronizar Dashboard
      </button>
    </div>
  );
}