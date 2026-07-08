import React, { useState, useEffect } from 'react';
import { Search, Terminal, AlertTriangle, Info, ShieldAlert, Download, Loader2 } from 'lucide-react';
import { apiGet } from '../api';

export default function Logs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filtro, setFiltro] = useState('ALL');
  const [busqueda, setBusqueda] = useState('');

  // --- OBTENER LOGS DE LA API EN TIEMPO REAL ---
  const cargarLogs = async () => {
    setLoading(true);
    try {
      // Si el filtro es ALL, llamamos a la raíz. Si no, le pasamos el query parameter a FastAPI.
      const url = filtro === 'ALL' ? '/api/v1/logs' : `/api/v1/logs?categoria=${filtro}`;
      const response = await apiGet(url);
      const data = await response.json();
      setLogs(data);
    } catch (error) {
      console.error("🚨 SIEM Error:", error);
    } finally {
      setLoading(false);
    }
  };

  // Recargar los logs cada vez que cambie el botón de filtro de severidad
  useEffect(() => {
    cargarLogs();
  }, [filtro]);

  // --- FILTRADO CONTEXTUAL EN EL FRONTEND (BUSCADOR) ---
  const logsFiltrados = logs.filter(log => {
    const texto = busqueda.toLowerCase();
    return (
      log.id.toString().includes(texto) ||
      log.operador.toLowerCase().includes(texto) ||
      log.accion.toLowerCase().includes(texto) ||
      log.origen_ip.includes(texto)
    );
  });

  // --- EXPORTAR REGISTROS A CSV ---
  const exportarCSV = () => {
    if (logsFiltrados.length === 0) return;
    
    const headers = ["ID Evento", "Nivel", "Operador", "Origen IP", "Accion", "Detalles", "Timestamp"];
    const rows = logsFiltrados.map(log => [
      `LOG-${log.id}`,
      log.categoria,
      log.operador,
      log.origen_ip,
      `"${log.accion.replace(/"/g, '""')}"`,
      `"${log.detalles.replace(/"/g, '""')}"`,
      log.timestamp
    ]);

    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `hyperion_audit_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

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
        <button 
          onClick={exportarCSV}
          disabled={loading || logsFiltrados.length === 0}
          className="bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-hyperion-lightBorder dark:border-slate-800 px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all shadow-sm disabled:opacity-40"
        >
          <Download size={16} /> Exportar CSV
        </button>
      </header>

      {/* Barra de Herramientas */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-white dark:bg-[#0b111e] border border-hyperion-lightBorder dark:border-slate-800/50 p-4 rounded-2xl shadow-sm dark:shadow-xl transition-colors">
        {/* Filtros */}
        <div className="flex gap-2 w-full md:w-auto overflow-x-auto">
          {['ALL', 'INFO', 'WARN', 'CRITICAL'].map((lvl) => (
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
            placeholder="Buscar operador, acción o IP..."
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
              {loading ? (
                <tr>
                  <td colSpan="5" className="px-6 py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2 font-sans italic">
                      <Loader2 className="animate-spin text-purple-500" size={18} />
                      Sincronizando registros inmutables con PostgreSQL...
                    </div>
                  </td>
                </tr>
              ) : logsFiltrados.length > 0 ? (
                logsFiltrados.map((log) => (
                  <tr key={log.id} className="hover:bg-purple-500/[0.02] dark:hover:bg-purple-500/[0.01] transition-colors font-mono">
                    <td className="px-6 py-4 text-slate-500 dark:text-slate-400 font-bold transition-colors">LOG-{log.id}</td>
                    <td className="px-6 py-4">
                      <span className={`flex items-center gap-1.5 font-bold ${log.categoria === 'CRITICAL' ? 'text-red-500 dark:text-red-400' : log.categoria === 'WARN' ? 'text-amber-500 dark:text-amber-400' : 'text-blue-500 dark:text-blue-400'
                        }`}>
                        {log.categoria === 'CRITICAL' && <ShieldAlert size={14} />}
                        {log.categoria === 'WARN' && <AlertTriangle size={14} />}
                        {log.categoria === 'INFO' && <Info size={14} />}
                        {log.categoria}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col font-sans">
                        <span className="text-slate-900 dark:text-slate-200 font-medium transition-colors">{log.operador}</span>
                        <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500 transition-colors">{log.origen_ip}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-slate-700 dark:text-slate-300 font-sans transition-colors">
                      <div className="flex flex-col">
                        <span>{log.accion}</span>
                        {log.detalles && <span className="text-[11px] font-mono text-slate-400 dark:text-slate-500 mt-0.5">{log.detalles}</span>}
                      </div>
                    </td>
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