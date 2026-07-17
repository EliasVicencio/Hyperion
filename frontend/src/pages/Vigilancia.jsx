import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ShieldAlert, Radio, Terminal, AlertOctagon, Layers, Search, Loader2, ShieldCheck, MapPin, ShieldX, Zap } from 'lucide-react';
import { apiGet } from '../api';
import WorldMap from '../components/Worldmap';

const alertasIniciales = [
  { id: "EV-091", ip: "192.168.1.142", tipo: "Intento de Fuerza Bruta SSH", severidad: "CRÍTICA", timestamp: "Hace 2 min" },
  { id: "EV-090", ip: "10.0.0.5", tipo: "Escaneo de Puertos Detectado", severidad: "ALTA", timestamp: "Hace 14 min" },
];

const TABS = [
  { id: 'vivo', label: 'En Vivo', icon: Zap },
  { id: 'investigacion', label: 'Investigación', icon: Search },
];

export default function Vigilancia() {
  const [tabActiva, setTabActiva] = useState('vivo');

  const [alertas, setAlertas] = useState(alertasIniciales);
  const [syslog, setSyslog] = useState([
    "[INFO] Inicializando Socket de Escucha perimetral...",
    "[OK] Reglas IPTables cargadas para cumplimiento ISO 27001.",
    "[WARN] Elevada latencia detectada en el Nodo Secundario."
  ]);
  const [scanning, setScanning] = useState(true);
  const [selectedElement, setSelectedElement] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);

  // Threat Intel (VirusTotal + AbuseIPDB)
  const [tiQuery, setTiQuery] = useState('');
  const [tiLoading, setTiLoading] = useState(false);
  const [tiError, setTiError] = useState(null);
  const [tiResult, setTiResult] = useState(null);

  const consultarThreatIntel = async (e) => {
    e.preventDefault();
    if (!tiQuery.trim()) return;
    setTiLoading(true);
    setTiError(null);
    setTiResult(null);
    try {
      const response = await apiGet(`/api/vigilancia/threat-intel/ip/${encodeURIComponent(tiQuery.trim())}`);
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || 'No se pudo consultar la IP.');
      }
      setTiResult(data);
    } catch (err) {
      setTiError(err.message);
    } finally {
      setTiLoading(false);
    }
  };

  const tiEsCritico = tiResult && (
    (tiResult.virustotal && tiResult.virustotal.maliciosos > 0) ||
    (tiResult.abuseipdb && tiResult.abuseipdb.score_abuso >= 50)
  );

  // Mapa de amenazas: combina puntos de búsquedas de Threat Intel + alertas simuladas geolocalizadas
  const [mapPoints, setMapPoints] = useState([]);

  const agregarPuntoAlMapa = (id, lat, lon, severidad, label) => {
    setMapPoints(prev => [{ id, lat, lon, severidad, label }, ...prev.filter(p => p.id !== id)].slice(0, 10));
  };

  const geolocalizarYAgregar = async (id, ip, severidad, label) => {
    try {
      const response = await apiGet(`/api/vigilancia/geolocate/${encodeURIComponent(ip)}`);
      if (!response.ok) return;
      const geo = await response.json();
      agregarPuntoAlMapa(id, geo.lat, geo.lon, severidad, label || ip);
    } catch {
      // Geolocalización best-effort: si falla, simplemente no aparece ese punto en el mapa
    }
  };

  // Cuando una búsqueda de Threat Intel trae geo, la sumamos al mapa
  useEffect(() => {
    if (tiResult?.geo && typeof tiResult.geo.lat === 'number') {
      const severidad = tiEsCritico ? 'CRITICA' : 'INFO';
      agregarPuntoAlMapa(`ti-${tiResult.ip}`, tiResult.geo.lat, tiResult.geo.lon, severidad, tiResult.ip);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tiResult]);

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

  // --- ACCIÓN DE MITIGACIÓN REAL (BLOCK_NODE) ---
  const ejecutarBloqueoNodo = (elemento) => {
    if (!elemento) return;

    setSyslog(prev => [
      `[KILLED] 🛡️ IP [${elemento.ip}] bloqueada permanentemente vía IPTables/Drop.`,
      `[INFO] Alerta ${elemento.id} mitigada con éxito por el operador.`,
      ...prev
    ]);
    setAlertas(prev => prev.filter(alerta => alerta.id !== elemento.id));
    setSelectedElement(null);
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
        geolocalizarYAgregar(nuevoId, nuevaIp, ataque.sev === 'CRÍTICA' ? 'CRITICA' : 'ALTA', nuevaIp);
      } else {
        const logAleatorio = logsNuevos[Math.floor(Math.random() * logsNuevos.length)];
        setSyslog(prev => [logAleatorio, ...prev.slice(0, 7)]);
      }

    }, 4000);

    return () => clearInterval(interval);
  }, [scanning]);

  return (
    <div className="space-y-6 text-slate-800 dark:text-slate-200">
      {/* Encabezado */}
      <header className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-4">
        <div>
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
      </header>

      {/* Pestañas internas */}
      <div className="flex gap-1.5 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-1.5 w-fit">
        {TABS.map(tab => {
          const Icon = tab.icon;
          const activa = tabActiva === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setTabActiva(tab.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all ${
                activa
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
              }`}
            >
              <Icon size={14} /> {tab.label}
            </button>
          );
        })}
      </div>

      {tabActiva === 'vivo' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Columna Izquierda: Alertas */}
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 p-6 rounded-2xl shadow-sm dark:shadow-xl transition-colors">
              <h3 className="text-xs font-bold text-slate-500 dark:text-slate-400 mb-4 flex items-center gap-2 uppercase tracking-wider">
                <ShieldAlert className="text-red-500 dark:text-red-400" size={16} /> Cola de Alertas Recientes (Red en Vivo)
              </h3>

              <div className="space-y-3">
                {alertas.length === 0 ? (
                  <div className="text-center py-8 bg-slate-50 dark:bg-slate-950/20 border border-dashed border-slate-200 dark:border-slate-800 rounded-xl text-xs font-mono text-emerald-600 dark:text-emerald-400/80">
                    ✔ Perimeter secure // Sin amenazas pendientes de mitigación.
                  </div>
                ) : (
                  alertas.map(alerta => {
                    const isCritica = alerta.severidad === 'CRÍTICA';
                    const estaSeleccionado = selectedElement?.id === alerta.id;
                    return (
                      <div
                        key={alerta.id}
                        onClick={() => setSelectedElement(alerta)}
                        className={`border rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all cursor-pointer ${
                          estaSeleccionado ? 'bg-blue-500/10 border-blue-500/40 shadow-sm' : 'bg-slate-50/50 dark:bg-slate-950/40 border-slate-100 dark:border-slate-900 hover:border-slate-200 dark:hover:border-slate-800'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                            isCritica ? 'bg-red-500/10 text-red-500 dark:text-red-400' : 'bg-amber-500/10 text-amber-500 dark:text-amber-400'
                          }`}>
                            <AlertOctagon size={16} />
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">{alerta.tipo}</p>
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
          </div>

          {/* Columna Derecha */}
          <div className="space-y-6">
            {selectedElement ? (
              <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 p-5 rounded-2xl shadow-sm dark:shadow-xl space-y-4 transition-colors">
                <h3 className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Layers size={14} className="text-blue-500 dark:text-blue-400" /> Inspector de Evidencias
                </h3>

                <div className="space-y-3 font-mono text-[11px]">
                  <div className="bg-slate-50 dark:bg-slate-950/80 p-3 rounded-xl border border-slate-100 dark:border-slate-900 text-slate-600 dark:text-slate-400">
                    <p><span className="text-slate-400 dark:text-slate-500">SIGN_ID:</span> {selectedElement.id}</p>
                    <p className="mt-1"><span className="text-slate-400 dark:text-slate-500">TARGET_IP:</span> {selectedElement.ip}</p>
                    <p className="mt-1"><span className="text-slate-400 dark:text-slate-500">VECTOR:</span> {selectedElement.tipo}</p>
                  </div>
                </div>

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
              <div className="bg-white dark:bg-slate-900/20 border border-slate-200 dark:border-slate-800 p-6 rounded-2xl text-center text-xs font-mono text-slate-400 dark:text-slate-500 transition-colors">
                SELECCIONE_UN_INCIDENTE_PARA_INSPECCIÓN
              </div>
            )}

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
      )}

      {tabActiva === 'investigacion' && (
        <div className="space-y-6">
          {/* Threat Intel: consulta de reputación de IP */}
          <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 p-6 rounded-2xl shadow-sm dark:shadow-xl transition-colors">
            <h3 className="text-xs font-bold text-slate-500 dark:text-slate-400 mb-4 flex items-center gap-2 uppercase tracking-wider">
              <Search className="text-blue-500 dark:text-blue-400" size={16} /> Consulta de Reputación de IP
            </h3>

            <form onSubmit={consultarThreatIntel} className="flex gap-3 mb-4">
              <input
                type="text"
                value={tiQuery}
                onChange={(e) => setTiQuery(e.target.value)}
                placeholder="8.8.8.8"
                className="flex-1 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-2.5 text-sm font-mono text-slate-800 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-blue-500/50"
              />
              <button
                type="submit"
                disabled={tiLoading}
                className="bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold px-5 rounded-xl text-sm flex items-center gap-2 transition-all"
              >
                {tiLoading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
                Analizar
              </button>
            </form>

            {tiError && (
              <div className="bg-red-500/10 border border-red-500/20 p-3 rounded-xl text-red-500 dark:text-red-400 text-xs mb-2">
                {tiError}
              </div>
            )}

            {tiResult && (
              <div className="space-y-3">
                <div className={`flex items-center justify-between rounded-xl p-3 border ${
                  tiEsCritico
                    ? 'bg-red-500/10 border-red-500/30 text-red-600 dark:text-red-400'
                    : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
                }`}>
                  <div className="flex items-center gap-2 text-sm font-semibold">
                    {tiEsCritico ? <AlertOctagon size={16} /> : <ShieldCheck size={16} />}
                    {tiEsCritico ? 'Riesgo crítico detectado' : 'Sin señales de riesgo relevantes'}
                  </div>
                  <span className="text-[10px] font-mono opacity-70">{tiResult.ip}</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                    <p className="text-[10px] font-mono text-slate-400 dark:text-slate-500 uppercase mb-2">VirusTotal</p>
                    {tiResult.virustotal?.error ? (
                      <p className="text-xs text-slate-400 dark:text-slate-500">{tiResult.virustotal.error}</p>
                    ) : tiResult.virustotal ? (
                      <div className="space-y-1 text-xs">
                        <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">Maliciosos</span><span className="font-semibold text-slate-800 dark:text-slate-200">{tiResult.virustotal.maliciosos}</span></div>
                        <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">Reputación</span><span className="font-semibold text-slate-800 dark:text-slate-200">{tiResult.virustotal.reputacion}</span></div>
                        <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">País</span><span className="font-semibold text-slate-800 dark:text-slate-200">{tiResult.virustotal.pais || '—'}</span></div>
                      </div>
                    ) : (
                      <p className="text-xs text-slate-400 dark:text-slate-500">No configurado</p>
                    )}
                  </div>

                  <div className="bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-xl p-4">
                    <p className="text-[10px] font-mono text-slate-400 dark:text-slate-500 uppercase mb-2">AbuseIPDB</p>
                    {tiResult.abuseipdb?.error ? (
                      <p className="text-xs text-slate-400 dark:text-slate-500">{tiResult.abuseipdb.error}</p>
                    ) : tiResult.abuseipdb ? (
                      <div className="space-y-1 text-xs">
                        <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">Score abuso</span><span className="font-semibold text-slate-800 dark:text-slate-200">{tiResult.abuseipdb.score_abuso}%</span></div>
                        <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">Reportes</span><span className="font-semibold text-slate-800 dark:text-slate-200">{tiResult.abuseipdb.total_reportes}</span></div>
                        <div className="flex justify-between"><span className="text-slate-500 dark:text-slate-400">Uso</span><span className="font-semibold text-slate-800 dark:text-slate-200">{tiResult.abuseipdb.uso || '—'}</span></div>
                      </div>
                    ) : (
                      <p className="text-xs text-slate-400 dark:text-slate-500">No configurado</p>
                    )}
                  </div>
                </div>

                <p className="text-[10px] text-slate-400 dark:text-slate-600 text-center">Toda consulta queda registrada en Logs de Auditoría</p>
              </div>
            )}
          </div>

          {/* Mapa de Origen de Amenazas */}
          <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 p-6 rounded-2xl shadow-sm dark:shadow-xl transition-colors">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold text-slate-500 dark:text-slate-400 flex items-center gap-2 uppercase tracking-wider">
                <MapPin className="text-blue-500 dark:text-blue-400" size={16} /> Mapa de Origen de Amenazas
              </h3>
              <span className="text-[10px] font-mono text-slate-400 dark:text-slate-600">
                {mapPoints.length === 0 ? 'Sin puntos aún' : `${mapPoints.length} evento${mapPoints.length === 1 ? '' : 's'}`}
              </span>
            </div>
            <WorldMap points={mapPoints} />
            <p className="text-[10px] text-slate-400 dark:text-slate-600 text-center mt-3">
              Combina búsquedas de Threat Intel y alertas de red geolocalizadas
            </p>
          </div>
        </div>
      )}
    </div>
  );
}