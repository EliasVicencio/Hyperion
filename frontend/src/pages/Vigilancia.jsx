import React, { useState, useEffect } from 'react';
import { ShieldAlert, Radio, Terminal, AlertOctagon, RefreshCw, Eye, ShieldX, KeyRound, Layers } from 'lucide-react';

const alertasIniciales = [
  { id: "EV-091", ip: "192.168.1.142", tipo: "Intento de Fuerza Bruta SSH", severidad: "CRÍTICA", timestamp: "Hace 2 min" },
  { id: "EV-090", ip: "10.0.0.5", tipo: "Escaneo de Puertos Detectado", severidad: "ALTA", timestamp: "Hace 14 min" },
];

export default function Vigilancia() {
  // Ahora la cola de alertas es un estado completamente dinámico
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

  // Sincronización real con tu API (PostgreSQL)
  const consultarStreamingLogs = async () => {
    setLoadingAPI(true);
    try {
      const response = await fetch('/api/v1/logs');
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

  // --- SONDA INTERACTIVA REFORZADA ---
  // Genera Syslogs Y inyecta Alertas Críticas reactivas en la cola superior
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

      // Decidimos aleatoriamente si este ciclo genera una alerta visual arriba (35% de probabilidad)
      const generarAlertaGrave = Math.random() < 0.35;

      if (generarAlertaGrave) {
        const ataque = vectoresAtaque[Math.floor(Math.random() * vectoresAtaque.length)];
        const nuevoId = `EV-${Math.floor(100 + Math.random() * 900)}`;
        const nuevaIp = `185.190.${Math.floor(1 * 254)}.${Math.floor(1 * 254)}`;
        
        const nuevaAlerta = {
          id: nuevoId,
          ip: nuevaIp,
          tipo: ataque.tipo,
          severidad: ataque.sev,
          timestamp: "En vivo"
        };

        // La agregamos al inicio de la lista de alertas y limitamos a un máximo de 4 para no romper el layout
        setAlertas(prev => [nuevaAlerta, ...prev.slice(0, 3)]);
        setSyslog(prev => [`[ALERT] Amenaza interceptada en red: ${ataque.tipo} desde IP ${nuevaIp}`, ...prev.slice(0, 6)]);
      } else {
        // Si no es alerta grave, solo empuja un log normal a la consola SIEM
        const logAleatorio = logsNuevos[Math.floor(Math.random() * logsNuevos.length)];
        setSyslog(prev => [logAleatorio, ...prev.slice(0, 7)]);
      }

    }, 4000); // Cada 4 segundos evalúa el tráfico

    return () => clearInterval(interval);
  }, [scanning]);

  return (
    <div className="space-y-6 text-slate-300">
      {/* Encabezado */}
      <header className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-red-600 to-amber-600 text-white shadow-[0_0_15px_rgba(239,68,68,0.3)]">
              <Radio className={scanning ? 'animate-pulse' : ''} size={22} />
            </div>
            Centro de Vigilancia
          </h1>
          <p className="text-slate-400 text-sm mt-1">Inspección de paquetes profunda e hilos de ejecución perimetrales en tiempo real</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={consultarStreamingLogs}
            className="bg-slate-900 text-slate-300 border border-slate-800 px-3 py-1.5 rounded-xl text-xs font-mono flex items-center gap-2 transition-all shadow-sm hover:bg-slate-800"
          >
            <RefreshCw size={12} className={loadingAPI ? "animate-spin" : ""} /> REFRESH_DB
          </button>
          <button
            onClick={() => setScanning(!scanning)}
            className={`px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 border transition-all ${
              scanning
                ? 'bg-red-500/10 text-red-400 border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.1)]'
                : 'bg-slate-900 text-slate-400 border-slate-800'
            }`}
          >
            {scanning ? 'Sonda Activa' : 'Sonda Pausada'}
          </button>
        </div>
      </header>

      {/* Grid de Tres Columnas */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Columna Izquierda: Listas de Eventos (Alertas + Logs de BD) */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Bloque A: Alertas de Red ¡AHORA DINÁMICAS! */}
          <div className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-6 shadow-xl backdrop-blur-sm">
            <h3 className="text-xs font-bold text-slate-400 mb-4 flex items-center gap-2 uppercase tracking-wider">
              <ShieldAlert className="text-red-400" size={16} /> Cola de Alertas Recientes (Red en Vivo)
            </h3>

            <div className="space-y-3">
              {alertas.map(alerta => {
                const isCritica = alerta.severidad === 'CRÍTICA';
                const estaSeleccionado = selectedElement?.id === alerta.id && selectedElement?.tipo_origen === 'ALERTA';
                
                return (
                  <div
                    key={alerta.id}
                    onClick={() => setSelectedElement({ ...alerta, tipo_origen: 'ALERTA' })}
                    className={`border rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all cursor-pointer ${
                      estaSeleccionado 
                        ? 'bg-red-500/10 border-red-500/40 shadow-lg' 
                        : 'bg-slate-950/40 border-slate-900 hover:border-slate-800'
                    }`}
                  >
                    <div className="flex items-start sm:items-center gap-3">
                      <div className={`p-2 rounded-lg border shrink-0 ${
                        isCritica 
                          ? 'bg-red-500/10 text-red-400 border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.1)]' 
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/20' 
                      }`}>
                        <AlertOctagon size={18} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-slate-200 font-semibold text-sm">{alerta.tipo}</span>
                          <span className="text-[10px] bg-slate-900 border border-slate-800 text-slate-400 px-1.5 py-0.5 rounded font-mono font-bold">{alerta.id}</span>
                        </div>
                        <p className="text-xs text-slate-500 mt-1 font-mono">Origen IP: <span className="text-slate-400">{alerta.ip}</span></p>
                      </div>
                    </div>
                    <div className="text-left sm:text-right shrink-0">
                      <span className={`text-[10px] font-extrabold px-2 py-0.5 rounded border tracking-wide ${
                        isCritica ? 'text-red-400 bg-red-950/40 border-red-900/30' : 'text-amber-400 bg-amber-950/40 border-amber-900/30'
                      }`}>
                        {alerta.severidad}
                      </span>
                      <span className={`text-[11px] block sm:mt-1 mt-2 font-mono ${alerta.timestamp === 'En vivo' ? 'text-red-400 animate-pulse font-bold' : 'text-slate-500'}`}>{alerta.timestamp}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Bloque B: Logs de Auditoría Real (Base de Datos / SGSI) */}
          <div className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-6 shadow-xl backdrop-blur-sm">
            <h3 className="text-xs font-bold text-slate-400 mb-4 flex items-center gap-2 uppercase tracking-wider">
              <Terminal className="text-blue-400" size={16} /> Logs de Eventos de Auditoría (PostgreSQL / Inmutables)
            </h3>
            <div className="space-y-3 max-h-60 overflow-y-auto pr-1">
              {logsReales.length === 0 ? (
                <div className="text-center py-6 text-slate-500 font-mono text-xs">NO_EVENTS_IN_DATABASE</div>
              ) : (
                logsReales.map(log => {
                  const estaSeleccionado = selectedElement?.id === log.id && selectedElement?.tipo_origen === 'BD';
                  return (
                    <div
                      key={log.id}
                      onClick={() => setSelectedElement({ ...log, tipo_origen: 'BD' })}
                      className={`border rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all cursor-pointer font-mono text-xs ${
                        estaSeleccionado 
                          ? 'bg-blue-500/10 border-blue-500/40 shadow-lg' 
                          : 'bg-slate-950/40 border-slate-900 hover:border-slate-800'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.4)]" />
                        <div>
                          <p className="text-slate-200 font-bold">{log.event_type || 'SYSTEM_EVENT'}</p>
                          <p className="text-[10px] text-slate-500 mt-0.5">Actor: <span className="text-slate-400">{log.actor || 'system'}</span> | Modulo: <span className="text-slate-400">{log.service || 'core'}</span></p>
                        </div>
                      </div>
                      <div className="text-left sm:text-right shrink-0">
                        <span className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[10px] font-bold">
                          {log.categoria || log.nivel || 'AUDIT'}
                        </span>
                        <span className="text-[10px] text-slate-500 block mt-1">
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

        {/* Columna Derecha: Inspector de Evidencias */}
        <div className="space-y-6">
          {selectedElement ? (
            <div className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-5 shadow-xl backdrop-blur-sm space-y-4">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Layers size={14} className="text-blue-400" /> Inspector de Evidencias
              </h3>

              {selectedElement.tipo_origen === 'BD' ? (
                <div className="space-y-3 font-mono text-[11px]">
                  <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-900">
                    <span className="text-slate-500 block text-[9px]">PREVIOUS_HASH:</span>
                    <span className="break-all text-slate-400 tracking-tighter">
                      {selectedElement.previous_hash || "0000000000000000000000000000000000000000000000000000000000000000"}
                    </span>
                  </div>
                  <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-900">
                    <span className="text-emerald-400 block text-[9px]">CURRENT_BLOCK_HASH (SHA-256):</span>
                    <span className="break-all font-bold text-emerald-400 tracking-tighter">
                      {selectedElement.current_hash || "Sello criptográfico activo"}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 bg-emerald-500/5 border border-emerald-500/20 text-emerald-400 p-2 rounded-xl text-[10px]">
                    <Eye size={12} /> Bloque auditado inmutable.
                  </div>
                </div>
              ) : (
                <div className="space-y-3 font-mono text-[11px]">
                  <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-900 text-slate-400">
                    <p><span className="text-slate-500">SIGN_ID:</span> {selectedElement.id}</p>
                    <p className="mt-1"><span className="text-slate-500">TARGET_IP:</span> {selectedElement.ip}</p>
                    <p className="mt-1"><span className="text-slate-500">VECTOR:</span> {selectedElement.tipo}</p>
                  </div>
                  <div className="flex items-center gap-2 bg-amber-500/5 border border-amber-500/20 text-amber-400 p-2 rounded-xl text-[10px]">
                    <AlertOctagon size={12} /> Alerta en caliente no consolidada en cadena.
                  </div>
                </div>
              )}

              <div className="pt-2 border-t border-slate-800/60 space-y-2">
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Acciones de Contramedida</span>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <button 
                    onClick={() => alert(`Baneando tráfico de la IP: ${selectedElement.ip || 'Local Node'}`)}
                    className="flex items-center justify-center gap-2 p-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-xl transition-all"
                  >
                    <ShieldX size={13} /> BLOCK_NODE
                  </button>
                  <button 
                    onClick={() => alert('Rotando firmas criptográficas perimetrales')}
                    className="flex items-center justify-center gap-2 p-2 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-xl transition-all"
                  >
                    <KeyRound size={13} /> ROTATE_KEY
                  </button>
                </div>
              </div>
            </div>
          ) : null}

          {/* Consola SIEM Live Feed */}
          <div className="bg-[#040712] border border-slate-900 rounded-2xl p-5 shadow-inner flex flex-col justify-between min-h-[280px]">
            <div>
              <div className="flex items-center justify-between border-b border-slate-900 pb-3 mb-4">
                <span className="text-xs font-bold text-slate-400 flex items-center gap-2 uppercase tracking-wider">
                  <Terminal size={14} className="text-blue-500" /> SIEM Live Feed
                </span>
                {scanning && <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>}
              </div>
              <div className="space-y-2.5 font-mono text-[11px] leading-relaxed max-h-[220px] overflow-y-auto pr-1 select-none">
                {syslog.map((log, index) => {
                  let logColor = 'text-slate-400';
                  if (log.includes('[ALERT]')) logColor = 'text-red-400 font-semibold';
                  else if (log.includes('[WARN]')) logColor = 'text-amber-400';
                  else if (log.includes('[OK]')) logColor = 'text-emerald-400';
                  else if (log.includes('[AUDIT]')) logColor = 'text-blue-400';

                  return (
                    <p key={index} className={logColor}>
                      {log}
                    </p>
                  );
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