import React, { useState } from 'react';
import { Search, Terminal, AlertTriangle, Info, ShieldAlert, Download } from 'lucide-react';

const logsIniciales = [
  { id: "LOG-4821", usuario: "Elias Vicencio", accion: "Modificación de políticas SGSI", ip: "192.168.1.12", nivel: "WARN", timestamp: "2026-07-04 17:42:11" },
  { id: "LOG-4820", usuario: "System Gateway", accion: "Sincronización de base de datos exitosa", ip: "127.0.0.1", nivel: "INFO", timestamp: "2026-07-04 17:40:00" },
  { id: "LOG-4819", usuario: "Desconocido", accion: "Fallo de autenticación repetido (API/V1/AUTH)", ip: "185.220.101.5", nivel: "CRIT", timestamp: "2026-07-04 17:35:54" },
  { id: "LOG-4818", usuario: "Operador Alpha", accion: "Consulta de tabla de usuarios (RBAC)", ip: "192.168.1.45", nivel: "INFO", timestamp: "2026-07-04 17:12:02" },
  { id: "LOG-4817", usuario: "Elias Vicencio", accion: "Revocación de accesos - Token expirado", ip: "192.168.1.12", nivel: "WARN", timestamp: "2026-07-04 16:58:30" },
];

export default function Logs() {
  const [filtro, setFiltro] = useState('ALL');
  const [busqueda, setBusqueda] = useState('');

  const logsFiltrados = logsIniciales.filter(log => {
    const coincideNivel = filtro === 'ALL' || log.nivel === filtro;
    const coincideTexto = log.usuario.toLowerCase().includes(busqueda.toLowerCase()) ||
      log.accion.toLowerCase().includes(busqueda.toLowerCase()) ||
      log.id.toLowerCase().includes(busqueda.toLowerCase());
    return coincideNivel && coincideTexto;
  });

  return (
    <div className="space-y-6">
      {/* Encabezado */}
      <header className="flex justify-between items-end flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-950 dark:text-white tracking-tight flex items-center gap-3 transition-colors">
            <Terminal className="text-purple-500" size={28} /> Logs de Auditoría
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm transition-colors">Registro inmutable de eventos del sistema e historial de acciones administrativas</p>
        </div>
        <button className="bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-hyperion-lightBorder dark:border-slate-800 px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all shadow-sm">
          <Download size={16} /> Exportar CSV
        </button>
      </header>

      {/* Barra de Herramientas */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-white dark:bg-[#0b111e] border border-hyperion-lightBorder dark:border-slate-800/50 p-4 rounded-2xl shadow-sm dark:shadow-xl transition-colors">
        {/* Filtros */}
        <div className="flex gap-2 w-full md:w-auto overflow-x-auto">
          {['ALL', 'INFO', 'WARN', 'CRIT'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFiltro(lvl)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono border transition-all ${filtro === lvl
                  ? 'bg-purple-600/10 text-purple-600 dark:text-purple-400 border-purple-500/30 shadow-sm'
                  : 'bg-slate-50 dark:bg-slate-950 text-slate-500 border-hyperion-lightBorder dark:border-slate-900 hover:text-slate-800 dark:hover:text-slate-300'
                }`}
            >
              {lvl === 'ALL' ? 'TODOS' : lvl}
            </button>
          ))}
        </div>

        {/* Buscador Contextual */}
        <div className="relative w-full md:w-72">
          <Search className="absolute left-3 top-2.5 text-slate-400 dark:text-slate-600" size={16} />
          <input
            type="text"
            placeholder="Buscar ID, usuario o acción..."
            className="bg-slate-50 dark:bg-slate-950 border border-hyperion-lightBorder dark:border-slate-900 rounded-xl py-2 pl-9 pr-4 w-full text-xs text-slate-800 dark:text-slate-300 focus:border-purple-500 outline-none transition-all"
            value={busqueda}
            onChange={(e) => setBusqueda(e.target.value)}
          />
        </div>
      </div>

      {/* Tabla de Logs */}
      <div className="bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/50 rounded-3xl overflow-hidden shadow-sm dark:shadow-2xl transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 dark:bg-slate-950/50 text-slate-500 dark:text-slate-400 uppercase text-[10px] tracking-widest transition-colors">
              <tr>
                <th className="px-6 py-4">ID Evento</th>
                <th className="px-6 py-4">Nivel</th>
                <th className="px-6 py-4">Usuario / Origen</th>
                <th className="px-6 py-4">Acción Ejecutada</th>
                <th className="px-6 py-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hyperion-lightBorder dark:divide-slate-800/40 text-xs md:text-sm transition-colors">
              {logsFiltrados.length > 0 ? (
                logsFiltrados.map((log) => (
                  <tr key={log.id} className="hover:bg-purple-500/[0.02] dark:hover:bg-purple-500/[0.01] transition-colors font-mono">
                    <td className="px-6 py-4 text-slate-500 dark:text-slate-400 font-bold transition-colors">{log.id}</td>
                    <td className="px-6 py-4">
                      <span className={`flex items-center gap-1.5 font-bold ${log.nivel === 'CRIT' ? 'text-red-500 dark:text-red-400' : log.nivel === 'WARN' ? 'text-amber-500 dark:text-amber-400' : 'text-blue-500 dark:text-blue-400'
                        }`}>
                        {log.nivel === 'CRIT' && <ShieldAlert size={14} />}
                        {log.nivel === 'WARN' && <AlertTriangle size={14} />}
                        {log.nivel === 'INFO' && <Info size={14} />}
                        {log.nivel}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col font-sans">
                        <span className="text-slate-900 dark:text-slate-200 font-medium transition-colors">{log.usuario}</span>
                        <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500 transition-colors">{log.ip}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-slate-700 dark:text-slate-300 font-sans transition-colors">{log.accion}</td>
                    <td className="px-6 py-4 text-slate-400 dark:text-slate-500 text-xs transition-colors">{log.timestamp}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" className="px-6 py-12 text-center text-slate-400 dark:text-slate-500 italic font-sans transition-colors">
                    No se encontraron registros que coincidan con los criterios de búsqueda.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}