import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, FileText, CheckCircle2, AlertTriangle, Fingerprint, Database, Search, ArrowRight, Play } from 'lucide-react';

export default function Gobernanza() {
  const [logs, setLogs] = useState([]);
  const [selectedLog, setSelectedLog] = useState(null);
  const [busqueda, setBusqueda] = useState("");
  
  // Estados para el Test de Integridad Masivo (ISO A.8.15)
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditStatus, setAuditStatus] = useState("CORRECTO"); // CORRECTO, AUDITING, COMPROMISED
  const [progresoAudit, setProgresoAudit] = useState(0);

  // 🔌 Cargar datos reales desde la API de Hyperion
  const cargarVerificacionCadena = async (mostrarAnimacion = false) => {
    if (mostrarAnimacion) {
      setIsAuditing(true);
      setProgresoAudit(0);
      setAuditStatus("AUDITING");
    }

    try {
      const response = await fetch('/api/v1/gobernanza/verificar-cadena');
      if (!response.ok) throw new Error("Error en la respuesta del servidor");
      const data = await response.json();
      
      const logsSeguros = data.logs || [];

      if (mostrarAnimacion) {
        let progreso = 0;
        const interval = setInterval(() => {
          progreso += 25;
          setProgresoAudit(progreso);
          
          if (progreso >= 100) {
            clearInterval(interval);
            setIsAuditing(false);
            setLogs(logsSeguros);
            
            const detectadoAtaque = logsSeguros.some(l => l.detalles && l.detalles.includes("ATAQUE"));
            setAuditStatus(detectadoAtaque ? "COMPROMISED" : "CORRECTO");
            
            if (logsSeguros.length > 0) {
              setSelectedLog(logsSeguros[0]);
            }
          }
        }, 200);
      } else {
        setLogs(logsSeguros);
        const detectadoAtaque = logsSeguros.some(l => l.detalles && l.detalles.includes("ATAQUE"));
        setAuditStatus(detectadoAtaque ? "COMPROMISED" : "CORRECTO");
        
        if (logsSeguros.length > 0 && !selectedLog) {
          setSelectedLog(logsSeguros[0]);
        }
      }
    } catch (error) {
      console.error("🚨 Error cargando datos de gobernanza:", error);
      setIsAuditing(false);
      setAuditStatus("COMPROMISED");
    }
  };

  useEffect(() => {
    cargarVerificacionCadena(false);
  }, []);

  const logsFiltrados = logs.filter(log => {
    const type = log.event_type ? log.event_type.toLowerCase() : "";
    const actor = log.actor ? log.actor.toLowerCase() : "";
    const control = log.control ? log.control.toLowerCase() : "";
    const termino = busqueda.toLowerCase();
    
    return type.includes(termino) || actor.includes(termino) || control.includes(termino);
  });

  const ejecutarAuditoriaISO = () => {
    cargarVerificacionCadena(true);
  };

  const simularInyeccionMaliciosa = async () => {
    try {
      const response = await fetch('/api/v1/gobernanza/simular-ataque', { method: 'POST' });
      if (!response.ok) throw new Error("Error al lanzar ataque");
      const data = await response.json();
      
      setAuditStatus("COMPROMISED");
      alert(`🚨 Simulación ejecutada: Registro ID #${data.target_id} manipulado directamente en la base de datos. Ejecuta el test ISO para comprobar la ruptura de hashes.`);
      
      cargarVerificacionCadena(false);
    } catch (error) {
      alert("No se pudo conectar con el endpoint de simulación.");
    }
  };

  return (
    <div className="space-y-6 text-slate-800 dark:text-slate-300">
      
      {/* Encabezado Principal */}
      <header className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 text-white shadow-[0_0_15px_rgba(59,130,246,0.3)]">
              <ShieldCheck size={22} />
            </div>
            Gobernanza y Cumplimiento Internacional
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">Garantía de inmutabilidad de registros y correlación criptográfica bajo el estándar <b>ISO/IEC 27001:2022</b></p>
        </div>
        
        <div className="flex gap-2">
          <button
            onClick={simularInyeccionMaliciosa}
            className="px-3 py-2 bg-red-50 dark:bg-red-950/40 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/40 rounded-xl text-xs font-mono font-bold hover:bg-red-100 dark:hover:bg-red-950/80 transition-all"
          >
            SIMULAR_ATTACK_BD
          </button>
          
          <button
            onClick={ejecutarAuditoriaISO}
            disabled={isAuditing}
            className={`px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 border font-mono transition-all ${
              auditStatus === "COMPROMISED" 
                ? 'bg-red-500 text-white border-red-600 shadow-[0_0_15px_rgba(239,68,68,0.4)]' 
                : 'bg-blue-600 hover:bg-blue-500 text-white border-blue-500 shadow-[0_0_15px_rgba(59,130,246,0.2)]'
            }`}
          >
            <Play size={14} className={isAuditing ? "animate-spin" : ""} /> 
            {isAuditing ? `AUDITANDO... ${progresoAudit}%` : 'VERIFICAR_CHAIN_ISO_27001'}
          </button>
        </div>
      </header>

      {/* PANEL DE MARCO REGLAMENTARIO (KPI CARDS) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Card 1: Estado de la cadena */}
        <div className={`p-4 rounded-2xl border bg-white dark:bg-slate-900/40 backdrop-blur-sm flex items-center gap-4 ${
          auditStatus === "CORRECTO" ? "border-emerald-200 dark:border-emerald-500/20" : auditStatus === "AUDITING" ? "border-blue-200 dark:border-blue-500/20" : "border-red-300 dark:border-red-500/40 bg-red-50 dark:bg-red-950/10"
        }`}>
          <div className={`p-3 rounded-xl ${
            auditStatus === "CORRECTO" ? "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" : auditStatus === "AUDITING" ? "bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400" : "bg-red-100 dark:bg-red-500/10 text-red-600 dark:text-red-400 animate-pulse"
          }`}>
            {auditStatus === "CORRECTO" ? <CheckCircle2 size={24} /> : auditStatus === "AUDITING" ? <Database size={24} className="animate-bounce" /> : <ShieldAlert size={24} />}
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 dark:text-slate-500 block">ISO A.8.15: Log Integrity</span>
            <span className={`text-sm font-mono font-bold ${
              auditStatus === "CORRECTO" ? "text-emerald-600 dark:text-emerald-400" : auditStatus === "AUDITING" ? "text-blue-600 dark:text-blue-400" : "text-red-600 dark:text-red-400 font-extrabold"
            }`}>
              {auditStatus === "CORRECTO" ? "✓ CADENA_INTEGRA" : auditStatus === "AUDITING" ? "RECALCULANDO_HASHES..." : "⚠ CADENA_CORRUMPIDA"}
            </span>
          </div>
        </div>

        {/* Card 2: Cobertura de Controles */}
        <div className="p-4 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900/40 backdrop-blur-sm flex items-center gap-4">
          <div className="p-3 rounded-xl bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400">
            <FileText size={24} />
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 dark:text-slate-500 block">Controles Mapeados</span>
            <span className="text-sm font-mono font-bold text-slate-700 dark:text-slate-200">A.8.12, A.8.15, A.8.24</span>
          </div>
        </div>

        {/* Card 3: Custodia criptográfica */}
        <div className="p-4 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900/40 backdrop-blur-sm flex items-center gap-4">
          <div className="p-3 rounded-xl bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400">
            <Fingerprint size={24} />
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 dark:text-slate-500 block">Sello Hash de Cierre</span>
            <span className="text-xs font-mono text-slate-600 dark:text-slate-400 truncate w-40 block">
              {logs && logs.length > 0 ? logs[0].current_hash : "Calculando..."}
            </span>
          </div>
        </div>

      </div>

      {/* GRID CENTRAL: TABLA E INSPECTOR */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* TABLA DE AUDITORÍA (Izquierda) */}
        <div className="lg:col-span-2 bg-white dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm dark:shadow-xl backdrop-blur-sm space-y-4">
          
          <div className="relative flex items-center">
            <Search className="absolute left-3.5 text-slate-400 dark:text-slate-500" size={16} />
            <input
              type="text"
              placeholder="Buscar por Evento, Actor o Control ISO (Ej: A.8.15)..."
              value={busqueda}
              onChange={(e) => setBusqueda(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded-xl text-xs font-mono text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:border-blue-500/50 transition-all"
            />
          </div>

          <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
            {logsFiltrados.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-slate-400 dark:text-slate-600">SISTEMA_SIN_REGISTROS_O_ESPERANDO_API</div>
            ) : (
              logsFiltrados.map(log => {
                const estaSeleccionado = selectedLog?.id === log.id;
                const esCritico = log.categoria === "CRÍTICO" || (log.detalles && log.detalles.includes("ATAQUE"));
                
                let badgeColor = esCritico 
                  ? "bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 border-red-100 dark:border-red-500/20" 
                  : log.categoria === "WARN" 
                    ? "bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-100 dark:border-amber-500/20" 
                    : "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-100 dark:border-emerald-500/20";
                
                let dotColor = esCritico ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]" : log.categoria === "WARN" ? "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.5)]" : "bg-emerald-400";

                return (
                  <div
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className={`border rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all cursor-pointer font-mono text-xs ${
                      estaSeleccionado 
                        ? 'bg-blue-50 dark:bg-blue-500/10 border-blue-300 dark:border-blue-500/40 shadow-sm' 
                        : 'bg-slate-50/50 dark:bg-slate-950/40 border-slate-100 dark:border-slate-900/60 hover:border-slate-200 dark:hover:border-slate-800'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <span className={`w-2 h-2 rounded-full ${dotColor}`} />
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="text-slate-800 dark:text-slate-200 font-bold">{log.event_type || "LOG"}</p>
                          <span className="text-[9px] px-1.5 py-0.2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-400 dark:text-slate-500 rounded font-bold font-sans">{log.control || "A.8.15"}</span>
                        </div>
                        <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">
                          Actor: <span className="text-slate-600 dark:text-slate-400">{log.actor}</span> | Nodo: <span className="text-slate-600 dark:text-slate-400">{log.service}</span>
                        </p>
                      </div>
                    </div>
                    
                    <div className="text-left sm:text-right shrink-0">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-extrabold tracking-wide ${badgeColor}`}>
                        {esCritico ? "CRÍTICO" : log.categoria || "INFO"}
                      </span>
                      <span className="text-[10px] text-slate-400 dark:text-slate-500 block mt-1.5">
                        {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "--:--:--"}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* INSPECTOR CRIPTOGRÁFICO DE BLOQUES (Derecha) */}
        <div className="space-y-4">
          {selectedLog ? (
            <div className="bg-white dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800/80 rounded-2xl p-5 shadow-sm dark:shadow-xl backdrop-blur-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/60 pb-3">
                <h3 className="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider flex items-center gap-2">
                  <Fingerprint size={14} className="text-indigo-500 dark:text-indigo-400" /> Sello de Inmutabilidad
                </h3>
                <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono font-bold">BLOCK_ID: #{selectedLog.id}</span>
              </div>

              <div className="space-y-3 font-mono text-[11px]">
                <div className="bg-slate-50 dark:bg-slate-950/80 p-3 rounded-xl border border-slate-100 dark:border-slate-900">
                  <span className="text-slate-400 dark:text-slate-500 block text-[9px] font-bold">PREVIOUS_BLOCK_HASH (A.8.15):</span>
                  <span className="break-all text-slate-600 dark:text-slate-400 tracking-tighter">{selectedLog.previous_hash || "000000000000..."}</span>
                </div>
                
                <div className="bg-slate-50 dark:bg-slate-950/80 p-3 rounded-xl border border-slate-100 dark:border-slate-900">
                  <span className="text-indigo-600 dark:text-indigo-400 block text-[9px] font-bold">CURRENT_BLOCK_HASH (SHA-256):</span>
                  <span className="break-all font-bold text-indigo-600 dark:text-indigo-400 tracking-tighter">{selectedLog.current_hash || "Generando..."}</span>
                </div>

                <div className="flex items-center justify-center text-slate-400 dark:text-slate-600 py-1">
                  <ArrowRight size={14} className="rotate-90" />
                </div>

                <div className="bg-slate-50/50 dark:bg-slate-950/40 p-3 rounded-xl border border-slate-100 dark:border-slate-900/60 text-slate-700 dark:text-slate-300 space-y-2">
                  <span className="text-slate-400 dark:text-slate-500 block text-[9px] font-bold">METADATOS INTEGRALES:</span>
                  <p className="text-[10px] leading-relaxed"><span className="text-slate-400 dark:text-slate-500">Payload:</span> {selectedLog.detalles || "Sin detalles"}</p>
                </div>
              </div>

              <div className="pt-2">
                {selectedLog.detalles && selectedLog.detalles.includes("ATAQUE") ? (
                  <div className="p-2.5 rounded-xl border text-[11px] font-mono flex items-center gap-2 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30 text-red-600 dark:text-red-400">
                    <AlertTriangle size={14} /> 
                    <span><b>CRITICAL_ERR:</b> Hash no coincide. ¡Payload manipulado en Supabase!</span>
                  </div>
                ) : (
                  <div className="p-2.5 rounded-xl border text-[11px] font-mono flex items-center gap-2 bg-emerald-50 dark:bg-emerald-500/5 border-emerald-100 dark:border-emerald-200 text-emerald-600 dark:text-emerald-400">
                    <CheckCircle2 size={14} /> 
                    <span>Firma criptográfica válida. Log inmutable.</span>
                  </div>
                )}
              </div>

            </div>
          ) : (
            <div className="bg-slate-50 dark:bg-slate-900/20 border border-slate-200 dark:border-slate-800 p-6 rounded-2xl text-center text-xs font-mono text-slate-400 dark:text-slate-500">
              SELECCIONE_UN_BLOQUE_PARA_VERIFICACIÓN
            </div>
          )}

          {/* Tarjeta explicativa ISO */}
          <div className="bg-slate-50 dark:bg-[#040712] border border-slate-200 dark:border-slate-900/80 rounded-2xl p-5 space-y-3">
            <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 flex items-center gap-1.5 uppercase font-mono">
              📋 Control Directiva A.8.15
            </span>
            <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
              El sistema genera firmas hash encadenadas utilizando <span className="text-slate-700 dark:text-slate-400">PostgreSQL + SHA-256</span>. Cualquier mutación no autorizada romperá la referencia secuencial, revocado el certificado de confianza de inmediato de acuerdo con las directrices de control de la norma ISO 27001.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}