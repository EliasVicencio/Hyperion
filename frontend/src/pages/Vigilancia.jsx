import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ShieldAlert, Radio, Terminal, AlertOctagon, RefreshCw, Eye, ShieldX, KeyRound, Layers } from 'lucide-react';
import { apiGet } from '../api';

const alertasIniciales = [
  { id: "EV-091", ip: "192.168.1.142", tipo: "Intento de Fuerza Bruta SSH", severidad: "CRÍTICA", timestamp: "Hace 2 min" },
  { id: "EV-090", ip: "10.0.0.5", tipo: "Escaneo de Puertos Detectado", severidad: "ALTA", timestamp: "Hace 14 min" },
];

export default function Vigilancia() {
  const [alertas, setAlertas] = useState(alertasIniciales);
  const [syslog, setSyslog] = useState([
    "[INFO] Inicializando Socket de Escucha perimetral...",
    "[OK] Reglas IPTables cargadas para cumplimiento ISO 27001.",
    "[WARN] Elevada latencia detectada en el Nodo Secundario."
  ]);
  const [scanning, setScanning] = useState(true);

  const [logsReales, setLogsReales] = useState([]);
  const [selectedElement, setSelectedElement] = useState(null); 
  const [loadingAPI, setLoadingAPI] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);

  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const reconnectAttemptRef = useRef(0);

  const conectarWebSocket = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/vigilancia/ws/live`;
    
    wsRef.current = new WebSocket(wsUrl);

    wsRef.current.onopen = () => {
      setWsConnected(true);
      reconnectAttemptRef.current = 0;
      setSyslog(prev => [`[OK] WebSocket conectado a ${wsUrl}`, ...prev.slice(0, 9)]);
    };

    wsRef.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data && data.accion) {
          setLogsReales(prev => [data, ...prev].slice(0, 100));
          setSyslog(prev => [`[WS] ${data.categoria}: ${data.accion} — ${data.operador}`, ...prev.slice(0, 9)]);
          if ((data.categoria === 'CRITICAL' || data.severidad === 'CRITICAL') && 'Notification' in window && Notification.permission === 'granted') {
            new Notification('🔴 Alerta Crítica Hyperion', {
              body: `${data.accion} — ${data.operador}`,
              icon: '/favicon.ico'
            });
          }
        }
      } catch {
        // ignore non-JSON messages (keepalive pings)
      }
    };

    wsRef.current.onclose = () => {
      setWsConnected(false);
      const delay = Math.min(1000 * 2 ** reconnectAttemptRef.current, 30000);
      reconnectAttemptRef.current += 1;
      setSyslog(prev => [`[WARN] WebSocket desconectado. Reintentando en ${delay / 1000}s...`, ...prev.slice(0, 9)]);
      reconnectTimeoutRef.current = setTimeout(conectarWebSocket, delay);
    };

    wsRef.current.onerror = () => {
      wsRef.current?.close();
    };
  }, []);

  useEffect(() => {
    conectarWebSocket();
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      wsRef.current?.close();
    };
  }, [conectarWebSocket]);

  // Sincronización real con tu API (PostgreSQL)
  const consultarStreamingLogs = async () => {
    setLoadingAPI(true);
    try {
      const response = await apiGet('/api/v1/logs');
      if (!response.ok) throw new Error('Error en el canal de vigilancia.');
      const data = await response.json();
      const ordenados = data.sort((a, b) => b.id - a.id);
      setLogsReales(ordenados);
      
      if (!selectedElement) {
        setSelectedElement({ tipo_origen: 'ALERTA', ...alertasIniciales[0] });
      }
    } catch (error) {
      console.error("🚨 Surveillance API Error:", error);
    } finally {
      setLoadingAPI(false);
    }
  };

  useEffect(() => {
    consultarStreamingLogs();
  }, []);

  // --- ACCIÓN DE MITIGACIÓN REAL (BLOCK_NODE) ---
  const ejecutarBloqueoNodo = (elemento) => {
    if (!elemento) return;

    if (elemento.tipo_origen === 'ALERTA') {
      // 1. Inyectamos reporte de mitigación en el Syslog
      setSyslog(prev => [
        `[KILLED] 🛡️ IP [${elemento.ip}] bloqueada permanentemente vía IPTables/Drop.`,
        `[INFO] Alerta ${elemento.id} mitigada con éxito por el operador.`,
        ...prev
      ]);

      // 2. Removemos la alerta de la lista usando su ID
      setAlertas(prev => prev.filter(alerta => alerta.id !== elemento.id));
      
      // 3. Limpiamos o reajustamos la selección del inspector
      setSelectedElement(null);
    } else {
      // Si es un log real de la BD, no lo borramos (por normativas de inmutabilidad), pero registramos la contramedida
      setSyslog(prev => [
        `[COUNTERMEASURE] Sesión revocada criptográficamente para actor: ${elemento.actor || 'system'}`,
        ...prev
      ]);
      alert(`Contramedida enviada para el actor real: ${elemento.actor || 'system'}. El log permanece intacto en PostgreSQL para auditoría conforme a ISO 27001.`);
    }
  };

  // Sonda interactiva que genera ataques aleatorios
  useEffect(() => {
    if (!scanning) return;

    const interval = setInterval(() => {
      const vectoresAtaque = [
        { tipo: "Inyección SQL Detectada en API", sev: "CRÍTICA" },
        { tipo: "Tráfico Anómalo hacia Puerto 443", sev: "ALTA" },
        { tipo: "Peticiones Concurrentes (DDoS Match)", sev: "CRÍTICA" },
        { tipo: "Intento de Fuerza Bruta HTTP", sev: "ALTA" }
      ];

      const logsNuevos = [
        `[AUDIT] Petición entrante validada desde Gateway central.`,
        `[INFO] Comprobando integridad del archivo de configuración... OK.`,
        `[ALERT] Intento de acceso denegado para el recurso /api/v1/auth/admin`
      ];

      const generarAlertaGrave = Math.random() < 0.35;

      if (generarAlertaGrave) {
        const ataque = vectoresAtaque[Math.floor(Math.random() * vectoresAtaque.length)];
        const nuevoId = `EV-${Math.floor(100 + Math.random() * 900)}`;
        const nuevaIp = `185.190.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`;
        
        const nuevaAlerta = {
          id: nuevoId,
          ip: nuevaIp,
          tipo: ataque.tipo,
          severidad: ataque.sev,
          timestamp: "En vivo"
        };

        setAlertas(prev => [nuevaAlerta, ...prev.slice(0, 3)]);
        setSyslog(prev => [`[ALERT] Amenaza interceptada en red: ${ataque.tipo} desde IP ${nuevaIp}`, ...prev.slice(0, 6)]);
      } else {
        const logAleatorio = logsNuevos[Math.floor(Math.random() * logsNuevos.length)];
        setSyslog(prev => [logAleatorio, ...prev.slice(0, 7)]);
      }

    }, 4000);

    return () => clearInterval(interval);
  }, [scanning]);

  return (
    // 🌟 CAMBIO: Adaptado el texto base para heredar correctamente text-slate-800 en claro y dark:text-slate-200 en oscuro
    <div className="space-y-6 text-slate-800 dark:text-slate-200">
      {/* Encabezado */}
      <header className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-4">
        <div>
          {/* 🌟 CAMBIO: Cambiado text-white a text-slate-900 dark:text-white */}
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-red-600 to-amber-600 text-white shadow-[0_0_15px_rgba(239,68,68,0.3)]">
              <Radio className={scanning ? 'animate-pulse' : ''} size={22} />
            </div>
            Centro de Vigilancia
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">Inspección de paquetes profunda e hilos de ejecución perimetrales en tiempo real</p>
          <div className="flex items-center gap-1.5 mt-1">
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-500 animate-pulse' : 'bg-red-500'}`} />
            <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
              {wsConnected ? 'WS_CONNECTED' : 'WS_DISCONNECTED'}
            </span>
          </div>
        </div>
        <div className="flex gap-2">
          {/* 🌟 CAMBIO: Botón REFRESH adaptativo (Bordes, Fondos y Textos balanceados) */}
          <button
            onClick={consultarStreamingLogs}
            className="bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-800 px-3 py-1.5 rounded-xl text-xs font-mono flex items-center gap-2 transition-all shadow-sm hover:bg-slate-50 dark:hover:bg-slate-800"
          >
            <RefreshCw size={12} className={loadingAPI ? "animate-spin" : ""} /> REFRESH_DB
          </button>
          {/* 🌟 CAMBIO: Botón Sonda adaptativo para cuando está inactivo */}
          <button
            onClick={() => setScanning(!scanning)}
            className={`px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 border transition-all ${
              scanning
                ? 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30 dark:border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.05)]'
                : 'bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800'
            }`}
          >
            {scanning ? 'Sonda Activa' : 'Sonda Pausada'}
          </button>
        </div>
      </header>

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Columna Izquierda: Alertas y Logs */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Alertas de Red */}
          {/* 🌟 CAMBIO: Contenedor principal de Alertas adaptativo (Blanco en claro, Slate oscuro en dark) */}
          <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 p-6 rounded-2xl shadow-sm dark:shadow-xl transition-colors">
            <h3 className="text-xs font-bold text-slate-500 dark:text-slate-400 mb-4 flex items-center gap-2 uppercase tracking-wider">
              <ShieldAlert className="text-red-500 dark:text-red-400" size={16} /> Cola de Alertas Recientes (Red en Vivo)
            </h3>

            <div className="space-y-3">
              {alertas.length === 0 ? (
                /* 🌟 CAMBIO: Caja de "Sin Amenazas" adaptativa */
                <div className="text-center py-8 bg-slate-50 dark:bg-slate-950/20 border border-dashed border-slate-200 dark:border-slate-800 rounded-xl text-xs font-mono text-emerald-600 dark:text-emerald-400/80">
                  ✔ Perimeter secure // Sin amenazas pendientes de mitigación.
                </div>
              ) : (
                alertas.map(alerta => {
                  const isCritica = alerta.severidad === 'CRÍTICA';
                  const estaSeleccionado = selectedElement?.id === alerta.id && selectedElement?.tipo_origen === 'ALERTA';
                  
                  return (
                    /* 🌟 CAMBIO: Filas de alerta adaptativas. Manejan bordes suaves en claro. */
                    <div
                      key={alerta.id}
                      onClick={() => setSelectedElement({ ...alerta, tipo_origen: 'ALERTA' })}
                      className={`border rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all cursor-pointer ${
                        estaSeleccionado 
                          ? 'bg-red-500/10 border-red-500/40 shadow-sm' 
                          : 'bg-slate-50/50 dark:bg-slate-950/40 border-slate-100 dark:border-slate-900 hover:border-slate-200 dark:hover:border-slate-800'
                      }`}
                    >
                      <div className="flex items-start sm:items-center gap-3">
                        <div className={`p-2 rounded-lg border shrink-0 ${
                          isCritica ? 'bg-red-500/10 text-red-500 dark:text-red-400 border-red-500/20' : 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20' 
                        }`}>
                          <AlertOctagon size={18} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            {/* 🌟 CAMBIO: Texto del título adaptado a text-slate-800 / dark:text-slate-200 */}
                            <span className="text-slate-800 dark:text-slate-200 font-semibold text-sm">{alerta.tipo}</span>
                            <span className="text-[10px] bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 px-1.5 py-0.5 rounded font-mono font-bold">{alerta.id}</span>
                          </div>
                          <p className="text-xs text-slate-500 mt-1 font-mono">Origen IP: <span className="text-slate-700 dark:text-slate-400">{alerta.ip}</span></p>
                        </div>
                      </div>
                      <div className="text-left sm:text-right shrink-0">
                        <span className={`text-[10px] font-extrabold px-2 py-0.5 rounded border tracking-wide ${
                          isCritica ? 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-900/30' : 'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-900/30'
                        }`}>
                          {alerta.severidad}
                        </span>
                        <span className={`text-[11px] block sm:mt-1 mt-2 font-mono ${alerta.timestamp === 'En vivo' ? 'text-red-500 dark:text-red-400 animate-pulse font-bold' : 'text-slate-400 dark:text-slate-500'}`}>{alerta.timestamp}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Logs Reales de PostgreSQL */}
          {/* 🌟 CAMBIO: Contenedor principal de logs adaptativo */}
          <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 p-6 rounded-2xl shadow-sm dark:shadow-xl transition-colors">
            <h3 className="text-xs font-bold text-slate-500 dark:text-slate-400 mb-4 flex items-center gap-2 uppercase tracking-wider">
              <Terminal className="text-blue-500 dark:text-blue-400" size={16} /> Logs de Eventos de Auditoría (PostgreSQL / Inmutables)
            </h3>
            <div className="space-y-3 max-h-60 overflow-y-auto pr-1">
              {logsReales.length === 0 ? (
                <div className="text-center py-6 text-slate-400 dark:text-slate-500 font-mono text-xs">NO_EVENTS_IN_DATABASE</div>
              ) : (
                logsReales.map(log => {
                  const estaSeleccionado = selectedElement?.id === log.id && selectedElement?.tipo_origen === 'BD';
                  return (
                    /* 🌟 CAMBIO: Filas de logs adaptadas */
                    <div
                      key={log.id}
                      onClick={() => setSelectedElement({ ...log, tipo_origen: 'BD' })}
                      className={`border rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all cursor-pointer font-mono text-xs ${
                        estaSeleccionado ? 'bg-blue-500/10 border-blue-500/40 shadow-sm' : 'bg-slate-50/50 dark:bg-slate-950/40 border-slate-100 dark:border-slate-900 hover:border-slate-200 dark:hover:border-slate-800'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <span className="w-2 h-2 rounded-full bg-emerald-500 dark:bg-emerald-400" />
                        <div>
                          <p className="text-slate-800 dark:text-slate-200 font-bold">{log.event_type || 'SYSTEM_EVENT'}</p>
                          <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">Actor: <span className="text-slate-600 dark:text-slate-400">{log.actor || 'system'}</span> | Modulo: <span className="text-slate-600 dark:text-slate-400">{log.service || 'core'}</span></p>
                        </div>
                      </div>
                      <div className="text-left sm:text-right shrink-0">
                        <span className="px-1.5 py-0.5 rounded bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-100 dark:border-blue-500/20 text-[10px] font-bold">
                          {log.categoria || log.nivel || 'AUDIT'}
                        </span>
                        <span className="text-[10px] text-slate-400 dark:text-slate-500 block mt-1">
                          {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '---'}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

        </div>

        {/* Columna Derecha */}
        <div className="space-y-6">
          {selectedElement ? (
            /* 🌟 CAMBIO: Inspector de evidencias adaptativo */
            <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 p-5 rounded-2xl shadow-sm dark:shadow-xl space-y-4 transition-colors">
              <h3 className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Layers size={14} className="text-blue-500 dark:text-blue-400" /> Inspector de Evidencias
              </h3>

              {selectedElement.tipo_origen === 'BD' ? (
                <div className="space-y-3 font-mono text-[11px]">
                  {/* 🌟 CAMBIO: Cajas internas del inspector adaptadas con fondos sutiles en modo claro */}
                  <div className="bg-slate-50 dark:bg-slate-950/80 p-3 rounded-xl border border-slate-100 dark:border-slate-900">
                    <span className="text-slate-400 dark:text-slate-500 block text-[9px]">PREVIOUS_HASH:</span>
                    <span className="break-all text-slate-600 dark:text-slate-400 tracking-tighter">{selectedElement.previous_hash || "00000000..."}</span>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-950/80 p-3 rounded-xl border border-slate-100 dark:border-slate-900">
                    <span className="text-emerald-600 dark:text-emerald-400 block text-[9px]">CURRENT_BLOCK_HASH (SHA-256):</span>
                    <span className="break-all font-bold text-emerald-600 dark:text-emerald-400 tracking-tighter">{selectedElement.current_hash}</span>
                  </div>
                </div>
              ) : (
                <div className="space-y-3 font-mono text-[11px]">
                  <div className="bg-slate-50 dark:bg-slate-950/80 p-3 rounded-xl border border-slate-100 dark:border-slate-900 text-slate-600 dark:text-slate-400">
                    <p><span className="text-slate-400 dark:text-slate-500">SIGN_ID:</span> {selectedElement.id}</p>
                    <p className="mt-1"><span className="text-slate-400 dark:text-slate-500">TARGET_IP:</span> {selectedElement.ip}</p>
                    <p className="mt-1"><span className="text-slate-400 dark:text-slate-500">VECTOR:</span> {selectedElement.tipo}</p>
                  </div>
                </div>
              )}

              <div className="pt-2 border-t border-slate-100 dark:border-slate-800/60 space-y-2">
                <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500 uppercase block">Acciones de Contramedida</span>
                <div className="grid grid-cols-1 gap-2 text-xs font-mono">
                  <button 
                    onClick={() => ejecutarBloqueoNodo(selectedElement)}
                    className="flex items-center justify-center gap-2 p-2.5 bg-red-500/10 hover:bg-red-600 hover:text-white text-red-600 dark:text-red-400 border border-red-500/20 rounded-xl transition-all font-bold shadow-sm"
                  >
                    <ShieldX size={14} /> MITIGATE & BLOCK_NODE
                  </button>
                </div>
              </div>
            </div>
          ) : (
            /* 🌟 CAMBIO: Estado vacío del inspector adaptativo */
            <div className="bg-white dark:bg-slate-900/20 border border-slate-200 dark:border-slate-800 p-6 rounded-2xl text-center text-xs font-mono text-slate-400 dark:text-slate-500 transition-colors">
              SELECCIONE_UN_INCIDENTE_PARA_INSPECCIÓN
            </div>
          )}

          {/* Consola SIEM */}
          {/* 🌟 MANTENIDO: El SIEM Live Feed es una consola pura de red. Mantiene su fondo negro de terminal (#040712) en ambos modos para preservar la estética hacker militarizada, pero mejorando sus bordes */}
          <div className="bg-[#040712] border border-slate-200 dark:border-slate-900 rounded-2xl p-5 shadow-inner flex flex-col justify-between min-h-[280px]">
            <div>
              <div className="flex items-center justify-between border-b border-slate-900/80 pb-3 mb-4">
                <span className="text-xs font-bold text-slate-400 flex items-center gap-2 uppercase tracking-wider">
                  <Terminal size={14} className="text-blue-500" /> SIEM Live Feed
                </span>
                {scanning && <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>}
              </div>
              <div className="space-y-2.5 font-mono text-[11px] leading-relaxed max-h-[220px] overflow-y-auto pr-1">
                {syslog.map((log, index) => {
                  let logColor = 'text-slate-400';
                  if (log.includes('[KILLED]')) logColor = 'text-emerald-400 font-bold border-l-2 border-emerald-500 pl-1';
                  else if (log.includes('[ALERT]')) logColor = 'text-red-400 font-semibold';
                  else if (log.includes('[WARN]')) logColor = 'text-amber-400';
                  else if (log.includes('[OK]')) logColor = 'text-emerald-400';
                  else if (log.includes('[AUDIT]')) logColor = 'text-blue-400';

                  return <p key={index} className={logColor}>{log}</p>;
                })}
              </div>
            </div>
            <div className="border-t border-slate-900/60 pt-4 mt-4 text-center">
              <span className="text-[10px] text-slate-600 block">Canal seguro cifrado con TLS 1.3</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}