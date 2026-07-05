import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, FileText, CheckCircle2, AlertTriangle, Fingerprint, Database, Search, ArrowRight, Play } from 'lucide-react';

// Datos iniciales simulados que reflejan los eventos mixtos de la base de datos
const logsAuditoriaIniciales = [
  { id: 104, control: "AU-2 / AU-12", event_type: "PERIMETER_MITIGATION", actor: "operador_sysadmin", service: "firewall-wm", categoria: "CRÍTICO", timestamp: "2026-07-05T12:10:00Z", previous_hash: "8f9e0a1b8cf0e7d...", current_hash: "b3d4e5f6a7b8c9d...", detalles: "Bloqueo e inmunización de vector: Inyección SQL Detectada en API desde IP 185.190.24.11" },
  { id: 103, control: "AU-2", event_type: "LOGIN_SUCCESS", actor: "admin_elias", service: "auth-service", categoria: "INFO", timestamp: "2026-07-05T11:55:00Z", previous_hash: "a1b2c3d4e5f6g7h...", current_hash: "8f9e0a1b8cf0e7d...", detalles: "Autenticación correcta en panel central vía pasarela perimetral." },
  { id: 102, control: "AU-6 / AU-9", event_type: "UNAUTHORIZED_API_CALL", actor: "anonymous", service: "gateway", categoria: "WARN", timestamp: "2026-07-05T11:40:00Z", previous_hash: "f5e6d7c8x9y0z1a...", current_hash: "a1b2c3d4e5f6g7h...", detalles: "Petición rechazada en /api/v1/auth/admin. Firma de token inválida." },
  { id: 101, control: "AU-2", event_type: "DB_BACKUP_EXPORT", actor: "system_cron", service: "backup-manager", categoria: "INFO", timestamp: "2026-07-05T10:00:00Z", previous_hash: "000000000000000...", current_hash: "f5e6d7c8x9y0z1a...", detalles: "Volcado de esquema relacional PostgreSQL completado y cifrado en frío." }
];

export default function Gobernanza() {
  const [logs, setLogs] = useState(logsAuditoriaIniciales);
  const [selectedLog, setSelectedLog] = useState(logsAuditoriaIniciales[0]);
  const [busqueda, setBusqueda] = useState("");
  
  // Estados para el Test de Integridad Masivo (AU-9)
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditStatus, setAuditStatus] = useState("CORRECTO"); // CORRECTO, AUDITING, COMPROMISED
  const [progresoAudit, setProgresoAudit] = useState(0);

  // Filtrar logs según la barra de búsqueda
  const logsFiltrados = logs.filter(log => 
    log.event_type.toLowerCase().includes(busqueda.toLowerCase()) ||
    log.actor.toLowerCase().includes(busqueda.toLowerCase()) ||
    log.control.toLowerCase().includes(busqueda.toLowerCase())
  );

  // --- SIMULADOR DE AUDITORÍA CRIPTOGRÁFICA MASIVA (NIST AU-9) ---
  const ejecutarAuditoriaNIST = () => {
    setIsAuditing(true);
    setProgresoAudit(0);
    setAuditStatus("AUDITING");

    let CurrentProgress = 0;
    const interval = setInterval(() => {
      CurrentProgress += 25;
      setProgresoAudit(CurrentProgress);

      if (CurrentProgress >= 100) {
        clearInterval(interval);
        setIsAuditing(false);
        setAuditStatus("CORRECTO");
      }
    }, 400);
  };

  // Función para corromper la base de datos intencionalmente (Para testing de resiliencia)
  const simularInyeccionMaliciosa = () => {
    setLogs(prev => {
      const modificados = [...prev];
      // Alteramos el texto del log intermedio sin recalcular hashes, rompiendo la inmutabilidad
      modificados[2] = {
        ...modificados[2],
        detalles: "ATAQUE_HACKER: Registro alterado por inyección directa en base de datos PostgreSQL."
      };
      return modificados;
    });
    setAuditStatus("COMPROMISED");
    alert("🚨 Simulación activada: Se alteró el registro #102 directamente en la BD. Ejecuta el test NIST para comprobar el quiebre de confianza.");
  };

  return (
    <div className="space-y-6 text-slate-300">
      
      {/* Encabezado Principal */}
      <header className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 text-white shadow-[0_0_15px_rgba(59,130,246,0.3)]">
              <ShieldCheck size={22} />
            </div>
            Gobernanza y Cumplimiento Federal
          </h1>
          <p className="text-slate-400 text-sm mt-1">Garantía de inmutabilidad de registros y correlación criptográfica bajo el estándar <b>NIST SP 800-53 Rev. 5</b></p>
        </div>
        
        <div className="flex gap-2">
          <button
            onClick={simularInyeccionMaliciosa}
            className="px-3 py-2 bg-red-950/40 text-red-400 border border-red-900/40 rounded-xl text-xs font-mono font-bold hover:bg-red-950/80 transition-all"
          >
            SIMULAR_ATTACK_BD
          </button>
          
          <button
            onClick={ejecutarAuditoriaNIST}
            disabled={isAuditing}
            className={`px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 border font-mono transition-all ${
              auditStatus === "COMPROMISED" 
                ? 'bg-red-500 text-white border-red-600 shadow-[0_0_15px_rgba(239,68,68,0.4)]' 
                : 'bg-blue-600 hover:bg-blue-500 text-white border-blue-500 shadow-[0_0_15px_rgba(59,130,246,0.2)]'
            }`}
          >
            <Play size={14} className={isAuditing ? "animate-spin" : ""} /> 
            {isAuditing ? `AUDITANDO... ${progresoAudit}%` : 'VERIFICAR_CHAIN_NIST'}
          </button>
        </div>
      </header>

      {/* --- PANEL DE MARCO REGLAMENTARIO (KPI CARDS NIST AU) --- */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Card 1: Estado de la cadena */}
        <div className={`p-4 rounded-2xl border bg-slate-900/40 backdrop-blur-sm flex items-center gap-4 ${
          auditStatus === "CORRECTO" ? "border-emerald-500/20" : auditStatus === "AUDITING" ? "border-blue-500/20" : "border-red-500/40 bg-red-950/10"
        }`}>
          <div className={`p-3 rounded-xl ${
            auditStatus === "CORRECTO" ? "bg-emerald-500/10 text-emerald-400" : auditStatus === "AUDITING" ? "bg-blue-500/10 text-blue-400" : "bg-red-500/10 text-red-400 animate-pulse"
          }`}>
            {auditStatus === "CORRECTO" ? <CheckCircle2 size={24} /> : auditStatus === "AUDITING" ? <Database size={24} className="animate-bounce" /> : <ShieldAlert size={24} />}
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 block">NIST AU-9: Log Integrity</span>
            <span className={`text-sm font-mono font-bold ${
              auditStatus === "CORRECTO" ? "text-emerald-400" : auditStatus === "AUDITING" ? "text-blue-400" : "text-red-400 font-extrabold"
            }`}>
              {auditStatus === "CORRECTO" ? "✓ CADENA_INTEGRA" : auditStatus === "AUDITING" ? "RECALCULANDO_HASHES..." : "⚠ CADENA_CORRUMPIDA"}
            </span>
          </div>
        </div>

        {/* Card 2: Cobertura de Controles */}
        <div className="p-4 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-sm flex items-center gap-4">
          <div className="p-3 rounded-xl bg-blue-500/10 text-blue-400">
            <FileText size={24} />
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 block">Controles Mapeados</span>
            <span className="text-sm font-mono font-bold text-slate-200">AU-2, AU-6, AU-9, AU-12</span>
          </div>
        </div>

        {/* Card 3: Custodia criptográfica */}
        <div className="p-4 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-sm flex items-center gap-4">
          <div className="p-3 rounded-xl bg-indigo-500/10 text-indigo-400">
            <Fingerprint size={24} />
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 block">Sello Hash de Cierre</span>
            <span className="text-xs font-mono text-slate-400 truncate w-40 block">{logs[0]?.current_hash || "Cargando..."}</span>
          </div>
        </div>

      </div>

      {/* --- GRID CENTRAL: TABLA E INSPECTOR --- */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* TABLA DE AUDITORÍA (Columna de la izquierda) */}
        <div className="lg:col-span-2 bg-slate-900/40 border border-slate-800/80 rounded-2xl p-6 shadow-xl backdrop-blur-sm space-y-4">
          
          {/* Barra de búsqueda interna */}
          <div className="relative flex items-center">
            <Search className="absolute left-3.5 text-slate-500" size={16} />
            <input
              type="text"
              placeholder="Buscar por Evento, Actor o Control NIST (Ej: AU-9)..."
              value={busqueda}
              onChange={(e) => setBusqueda(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-950/60 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50 transition-all"
            />
          </div>

          {/* Listado de Logs consolidados */}
          <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
            {logsFiltrados.map(log => {
              const estaSeleccionado = selectedLog?.id === log.id;
              
              let badgeColor = "bg-blue-500/10 text-blue-400 border-blue-500/20";
              let dotColor = "bg-blue-400";
              
              if (log.categoria === "CRÍTICO") {
                badgeColor = "bg-red-500/10 text-red-400 border-red-500/20";
                dotColor = "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]";
              } else if (log.categoria === "WARN") {
                badgeColor = "bg-amber-500/10 text-amber-400 border-amber-500/20";
                dotColor = "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.5)]";
              } else {
                badgeColor = "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
                dotColor = "bg-emerald-400";
              }

              return (
                <div
                  key={log.id}
                  onClick={() => setSelectedLog(log)}
                  className={`border rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-all cursor-pointer font-mono text-xs ${
                    estaSeleccionado ? 'bg-blue-500/10 border-blue-500/40 shadow-md' : 'bg-slate-950/40 border-slate-900/60 hover:border-slate-800'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className={`w-2 h-2 rounded-full ${dotColor}`} />
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="text-slate-200 font-bold">{log.event_type}</p>
                        <span className="text-[9px] px-1.5 py-0.2 bg-slate-900 border border-slate-800 text-slate-500 rounded font-bold font-sans">{log.control}</span>
                      </div>
                      <p className="text-[10px] text-slate-500 mt-1">
                        Actor: <span className="text-slate-400">{log.actor}</span> | Nodo: <span className="text-slate-400">{log.service}</span>
                      </p>
                    </div>
                  </div>
                  
                  <div className="text-left sm:text-right shrink-0">
                    <span className={`px-2 py-0.5 rounded border text-[10px] font-extrabold tracking-wide ${badgeColor}`}>
                      {log.categoria}
                    </span>
                    <span className="text-[10px] text-slate-500 block mt-1.5">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* INSPECTOR CRIPTOGRÁFICO DE BLOQUES (Columna de la derecha) */}
        <div className="space-y-4">
          {selectedLog ? (
            <div className="bg-slate-900/40 border border-slate-800/80 rounded-2xl p-5 shadow-xl backdrop-blur-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/60 pb-3">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Fingerprint size={14} className="text-indigo-400" /> Sello de Inmutabilidad
                </h3>
                <span className="text-[10px] text-slate-500 font-mono font-bold">BLOCK_ID: #{selectedLog.id}</span>
              </div>

              {/* Hashes de la Cadena */}
              <div className="space-y-3 font-mono text-[11px]">
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-900">
                  <span className="text-slate-500 block text-[9px] font-bold">PREVIOUS_BLOCK_HASH (AU-9):</span>
                  <span className="break-all text-slate-400 tracking-tighter">{selectedLog.previous_hash}</span>
                </div>
                
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-900">
                  <span className="text-indigo-400 block text-[9px] font-bold">CURRENT_BLOCK_HASH (SHA-256):</span>
                  <span className="break-all font-bold text-indigo-400 tracking-tighter">{selectedLog.current_hash}</span>
                </div>

                {/* Encadenamiento lógico */}
                <div className="flex items-center justify-center text-slate-600 py-1">
                  <ArrowRight size={14} className="rotate-90" />
                </div>

                {/* Detalles completos en claro */}
                <div className="bg-slate-950/40 p-3 rounded-xl border border-slate-900/60 text-slate-300 space-y-2">
                  <span className="text-slate-500 block text-[9px] font-bold">METADATOS INTEGRALES:</span>
                  <p className="text-[10px] leading-relaxed"><span className="text-slate-500">Payload:</span> {selectedLog.detalles}</p>
                </div>
              </div>

              {/* Botón de verificación individual */}
              <div className="pt-2">
                <div className={`p-2.5 rounded-xl border text-[11px] font-mono flex items-center gap-2 ${
                  auditStatus === "COMPROMISED" && selectedLog.id === 102 
                    ? "bg-red-500/10 border-red-500/30 text-red-400" 
                    : "bg-emerald-500/5 border-emerald-500/20 text-emerald-400"
                }`}>
                  {auditStatus === "COMPROMISED" && selectedLog.id === 102 ? (
                    <>
                      <AlertTriangle size={14} /> 
                      <span><b>CRITICAL_ERR:</b> Hash no coincide. ¡Payload manipulado de forma externa!</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle2 size={14} /> 
                      <span>Firma criptográfica válida. Log inmutable.</span>
                    </>
                  )}
                </div>
              </div>

            </div>
          ) : (
            <div className="bg-slate-900/20 border border-slate-800 p-6 rounded-2xl text-center text-xs font-mono text-slate-500">
              SELECCIONE_UN_BLOQUE_PARA_VERIFICACIÓN
            </div>
          )}

          {/* Tarjeta explicativa NIST para el Oficial de Seguridad */}
          <div className="bg-[#040712] border border-slate-900/80 rounded-2xl p-5 space-y-3">
            <span className="text-[11px] font-bold text-slate-400 flex items-center gap-1.5 uppercase font-mono">
              📋 Control Directiva AU-9
            </span>
            <p className="text-[10px] font-mono text-slate-500 leading-relaxed">
              El sistema genera firmas hash encadenadas utilizando <span className="text-slate-400">PostgreSQL + SHA-256</span>. Cualquier mutación no autorizada romperá la referencia secuencial, revocando el certificado de confianza de inmediato.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}