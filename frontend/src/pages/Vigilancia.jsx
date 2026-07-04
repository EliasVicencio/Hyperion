import React, { useState, useEffect } from 'react';
import { ShieldAlert, ShieldCheck, Radio, Terminal, Eye, AlertOctagon, RefreshCw } from 'lucide-react';

// Datos estáticos iniciales en caso de que la API tarde en responder
const alertasIniciales = [
  { id: "EV-091", ip: "192.168.1.142", tipo: "Intento de Fuerza Bruta SSH", severidad: "CRÍTICA", timestamp: "Hace 2 min" },
  { id: "EV-090", ip: "10.0.0.5", tipo: "Escaneo de Puertos Detectado", severidad: "ALTA", timestamp: "Hace 14 min" },
  { id: "EV-089", ip: "185.220.101.3", tipo: "IP en Lista Negra Tor Node", severidad: "MEDIA", timestamp: "Hace 1 hora" },
];

export default function Vigilancia() {
  const [alertas, setAlertas] = useState(alertasIniciales);
  const [syslog, setSyslog] = useState([
    "[INFO] Inicializando Socket de Escucha perimetral...",
    "[OK] Reglas IPTables cargadas para cumplimiento ISO 27001.",
    "[WARN] Elevada latencia detectada en el Nodo Secundario."
  ]);
  const [scanning, setScanning] = useState(true);

  // Efecto de simulación para el feed de la consola del SIEM
  useEffect(() => {
    const interval = setInterval(() => {
      const logsNuevos = [
        `[AUDIT] Petición entrante validada desde Gateway central.`,
        `[INFO] Comprobando integridad del archivo de configuración... OK.`,
        `[ALERT] Intento de acceso denegado para el recurso /api/v1/auth/admin`
      ];
      const logAleatorio = logsNuevos[Math.floor(Math.random() * logsNuevos.length)];
      setSyslog(prev => [logAleatorio, ...prev.slice(0, 5)]);
    }, 4000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Encabezado */}
      <header className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
            <Radio className="text-red-500 animate-pulse" size={28} /> Centro de Vigilancia
          </h1>
          <p className="text-slate-500 text-sm">Inspección de paquetes profunda e hilos de ejecución perimetrales en tiempo real</p>
        </div>
        <button 
          onClick={() => setScanning(!scanning)}
          className={`px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 border transition-all ${
            scanning 
              ? 'bg-red-500/10 text-red-400 border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.1)]' 
              : 'bg-slate-900 text-slate-400 border-slate-800'
          }`}
        >
          <RefreshCw size={16} className={scanning ? 'animate-spin' : ''} />
          {scanning ? 'Sonda Activa' : 'Sonda Pausada'}
        </button>
      </header>

      {/* Panel de Control Dual */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Columna Izquierda: Alertas Activas (Ocupa 2 cols) */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-hyperion-card border border-slate-800/50 rounded-3xl p-6 shadow-2xl">
            <h3 className="text-sm font-semibold text-slate-400 mb-4 flex items-center gap-2 uppercase tracking-wider">
              <ShieldAlert className="text-red-400" size={18} /> Cola de Alertas Recientes
            </h3>
            
            <div className="space-y-3">
              {alertas.map(alerta => (
                <div 
                  key={alerta.id} 
                  className="bg-slate-950/60 border border-slate-900 rounded-2xl p-4 flex items-center justify-between hover:border-slate-800 transition-colors group"
                >
                  <div className="flex items-center gap-4">
                    <div className={`p-2 rounded-xl border ${
                      alerta.severidad === 'CRÍTICA' 
                        ? 'bg-red-500/10 text-red-400 border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.1)]' 
                        : alerta.severidad === 'ALTA'
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                        : 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                    }`}>
                      <AlertOctagon size={20} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-200 font-semibold text-sm">{alerta.tipo}</span>
                        <span className="text-[10px] bg-slate-900 text-slate-500 px-1.5 py-0.5 rounded font-mono font-bold">{alerta.id}</span>
                      </div>
                      <p className="text-xs text-slate-500 mt-0.5 font-mono">Origen IP: <span className="text-slate-400">{alerta.ip}</span></p>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      alerta.severidad === 'CRÍTICA' ? 'text-red-400 bg-red-950/30' : 'text-amber-400 bg-amber-950/30'
                    }`}>
                      {alerta.severidad}
                    </span>
                    <span className="text-[11px] text-slate-600 block mt-1">{alerta.timestamp}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Columna Derecha: Consola / Estado de las Reglas (Ocupa 1 col) */}
        <div className="space-y-6">
          {/* Tarjeta Consola de Syslog */}
          <div className="bg-[#050810] border border-slate-900 rounded-3xl p-5 shadow-inner flex flex-col h-full justify-between">
            <div>
              <div className="flex items-center justify-between border-b border-slate-900 pb-3 mb-4">
                <span className="text-xs font-semibold text-slate-400 flex items-center gap-2 uppercase tracking-wider">
                  <Terminal size={14} className="text-blue-500" /> SIEM Live Feed
                </span>
                <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping"></span>
              </div>
              <div className="space-y-2.5 font-mono text-[11px] leading-relaxed">
                {syslog.map((log, index) => (
                  <p 
                    key={index} 
                    className={`${
                      log.includes('[ALERT]') ? 'text-red-400' : log.includes('[WARN]') ? 'text-amber-400' : log.includes('[OK]') ? 'text-emerald-400' : 'text-slate-400'
                    }`}
                  >
                    {log}
                  </p>
                ))}
              </div>
            </div>
            <div className="border-t border-slate-900 pt-4 mt-6 text-center">
              <span className="text-[10px] text-slate-600 block">Canal seguro cifrado con TLS 1.3</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}