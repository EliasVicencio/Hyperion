import React, { useState, useEffect } from 'react';
import { Database, ShieldAlert, Users, Server, Layers, AlertTriangle, TrendingUp, CheckCircle } from 'lucide-react';

export default function ActivosRiesgos() {
  const [activos, setActivos] = useState([]);
  const [riesgos, setRiesgos] = useState([]);
  const [loading, setLoading] = useState(true);

  const cargarDatos = async () => {
    try {
      const res = await fetch('/api/v1/riesgos/dashboard');
      if (!res.ok) throw new Error("Error en la API");
      const data = await res.json();
      setActivos(data.activos || []);
      setRiesgos(data.matriz_riesgos || []);
    } catch (e) {
      console.error("Error al mapear ISO 27005:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    cargarDatos();
  }, []);

  // Función auxiliar para colores del nivel de riesgo (ISO 27005: 1-25)
  const getRiesgoBadge = (nivel) => {
    if (nivel >= 15) return "bg-red-500/10 text-red-500 border-red-500/20";
    if (nivel >= 8) return "bg-amber-500/10 text-amber-500 border-amber-500/20";
    return "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";
  };

  if (loading) return <div className="p-8 text-center font-mono text-xs text-slate-400">CARGANDO_INVENTARIO_Y_RIESGOS_ISO...</div>;

  return (
    <div className="space-y-6 text-slate-800 dark:text-slate-300">
      <header>
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-600 to-purple-600 text-white shadow-md">
            <Layers size={22} />
          </div>
          Inventario de Activos y Matriz de Riesgos
        </h1>
        <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
          Mapeo y evaluación automatizada bajo directrices de las normas <b>ISO/IEC 27001:2022 (A.5)</b> e <b>ISO 27005</b>.
        </p>
      </header>

      {/* SECCIÓN 1: INVENTARIO DE ACTIVOS (A.5) */}
      <section className="space-y-3">
        <h2 className="text-sm font-bold font-mono tracking-wider text-slate-400 uppercase">📋 CONTROL A.5: Inventario de Activos de Información</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {activos.map(activo => (
            <div key={activo.id} className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900/40 backdrop-blur-sm flex flex-col justify-between space-y-4">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-indigo-500">
                    {activo.tipo === 'Base de Datos' ? <Database size={18} /> : <Server size={18} />}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold font-mono text-slate-900 dark:text-white">{activo.nombre}</h3>
                    <span className="text-[10px] font-mono text-slate-400">{activo.tipo}</span>
                  </div>
                </div>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-extrabold border ${
                  activo.estado === 'SALUDABLE' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20 animate-pulse'
                }`}>
                  {activo.estado}
                </span>
              </div>
              
              <div className="pt-2 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span className="flex items-center gap-1"><Users size={12}/> {activo.responsable}</span>
                <span>Crit: <b className="text-slate-600 dark:text-slate-200">{activo.criticidad}</b></span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* SECCIÓN 2: MATRIZ DE RIESGO CUANTIFICADA (ISO 27005) */}
      <section className="space-y-3">
        <h2 className="text-sm font-bold font-mono tracking-wider text-slate-400 uppercase">📊 MATRIZ ISO 27005: Cuantificación del Riesgo Tecnológico</h2>
        <div className="bg-white dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800/80 rounded-2xl overflow-hidden shadow-sm backdrop-blur-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 dark:bg-slate-950/40 text-slate-400 dark:text-slate-500 border-b border-slate-100 dark:border-slate-800/80">
                  <th className="p-4 font-bold">ACTIVO</th>
                  <th className="p-4 font-bold">AMENAZA IDENTIFICADA</th>
                  <th className="p-4 text-center font-bold">PROB (1-5)</th>
                  <th className="p-4 text-center font-bold">IMPACTO (1-5)</th>
                  <th className="p-4 text-center font-bold">NIVEL RIESGO</th>
                  <th className="p-4 font-bold">ESTADO MITIGACIÓN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-700 dark:text-slate-300">
                {riesgos.map(riesgo => (
                  <tr key={riesgo.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-950/20 transition-all">
                    <td className="p-4 font-bold text-slate-900 dark:text-slate-200">{riesgo.activo_name}</td>
                    <td className="p-4 flex items-center gap-2"><AlertTriangle size={14} className="text-amber-500 shrink-0"/> {riesgo.amenaza}</td>
                    <td className="p-4 text-center text-slate-400">{riesgo.probabilidad}</td>
                    <td className="p-4 text-center text-slate-400">{riesgo.impacto}</td>
                    <td className="p-4 text-center">
                      <span className={`px-2.5 py-1 rounded border font-extrabold text-[11px] ${getRiesgoBadge(riesgo.nivel)}`}>
                        {riesgo.nivel} / 25
                      </span>
                    </td>
                    <td className="p-4">
                      <span className={`text-[10px] uppercase font-bold flex items-center gap-1.5 ${
                        riesgo.estado === 'MITIGADO' ? 'text-emerald-500' : riesgo.estado === 'EN_PROCESO' ? 'text-amber-500' : 'text-slate-400'
                      }`}>
                        {riesgo.estado === 'MITIGADO' ? <CheckCircle size={12}/> : <TrendingUp size={12}/>}
                        {riesgo.estado}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}