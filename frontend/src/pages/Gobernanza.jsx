import React, { useState } from 'react';
import { FileText, ShieldCheck, AlertCircle, CheckCircle2, ArrowUpRight, Scale, Clock } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const datosDominios = [
  { name: 'A.5 Organizacionales', cumplimiento: 85 },
  { name: 'A.6 Personas', cumplimiento: 100 },
  { name: 'A.7 Físicos', cumplimiento: 60 },
  { name: 'A.8 Tecnológicos', cumplimiento: 74 },
];

export default function Gobernanza() {
  const [politicas] = useState([
    { id: "POL-01", titulo: "Política de Control de Acceso", version: "v2.1", estado: "Aprobada", revisada: "2026-05-10" },
    { id: "POL-02", titulo: "Plan de Respuesta a Incidentes", version: "v1.4", estado: "Aprobada", revisada: "2026-06-01" },
    { id: "POL-03", titulo: "Gestión de Activos y Clasificación", version: "v1.0", estado: "En Revisión", revisada: "2026-06-28" },
    { id: "POL-04", titulo: "Política de Cifrado y Criptografía", version: "v3.0", estado: "Expirada", revisada: "2025-04-15" },
  ]);

  return (
    <div className="space-y-6">
      {/* Encabezado */}
      <header className="flex justify-between items-end flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-950 dark:text-white tracking-tight flex items-center gap-3 transition-colors">
            <Scale className="text-blue-500" size={28} /> Gobernanza y Cumplimiento
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm transition-colors">Alineación con el SGSI e inspección de controles del Anexo A de la norma ISO/IEC 27001:2022</p>
        </div>
        <div className="bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 px-4 py-2 rounded-xl text-xs font-mono font-bold shadow-sm transition-colors">
          Índice Global: <span className="text-slate-900 dark:text-white text-sm font-sans pl-1">79.7%</span>
        </div>
      </header>

      {/* Grid de Estado de Controles */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gráfico de Barras */}
        <div className="lg:col-span-2 bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/50 p-6 rounded-3xl shadow-sm dark:shadow-2xl transition-colors">
          <h3 className="text-sm font-semibold text-slate-400 mb-6 uppercase tracking-wider">Desglose de Controles (Anexo A)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={datosDominios} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#64748b" opacity={0.15} horizontal={false} />
                <XAxis type="number" domain={[0, 100]} stroke="#64748b" fontSize={11} tickFormatter={(v) => `${v}%`} />
                <YAxis dataKey="name" type="category" stroke="#64748b" fontSize={11} width={120} />
                <Tooltip
                  cursor={{ fill: 'rgba(100, 116, 139, 0.1)' }}
                  contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '12px', color: '#0f172a' }}
                  className="dark:[&>.recharts-default-tooltip]:!bg-[#070b14] dark:[&>.recharts-default-tooltip]:!border-[#1e293b] dark:[&>.recharts-default-tooltip]:!text-[#f8fafc]"
                />
                <Bar dataKey="cumplimiento" fill="#3b82f6" radius={[0, 6, 6, 0]} barSize={16} name="Cumplimiento %" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Resumen Ejecutivo del SGSI */}
        <div className="bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/50 p-6 rounded-3xl shadow-sm dark:shadow-2xl flex flex-col justify-between transition-colors">
          <div>
            <h3 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wider">Métricas de Auditoría</h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center bg-slate-50 dark:bg-slate-950/40 p-3 rounded-xl border border-hyperion-lightBorder dark:border-slate-900 transition-colors">
                <span className="text-xs text-slate-600 dark:text-slate-400 flex items-center gap-2"><CheckCircle2 size={14} className="text-emerald-500 dark:text-emerald-400" /> Controles Implementados</span>
                <span className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200">68 / 93</span>
              </div>
              <div className="flex justify-between items-center bg-slate-50 dark:bg-slate-950/40 p-3 rounded-xl border border-hyperion-lightBorder dark:border-slate-900 transition-colors">
                <span className="text-xs text-slate-600 dark:text-slate-400 flex items-center gap-2"><Clock size={14} className="text-amber-500 dark:text-amber-400" /> Controles en Desarrollo</span>
                <span className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200">18 / 93</span>
              </div>
              <div className="flex justify-between items-center bg-slate-50 dark:bg-slate-950/40 p-3 rounded-xl border border-hyperion-lightBorder dark:border-slate-900 transition-colors">
                <span className="text-xs text-slate-600 dark:text-slate-400 flex items-center gap-2"><AlertCircle size={14} className="text-red-500 dark:text-red-400" /> Brechas Críticas</span>
                <span className="text-xs font-mono font-bold text-red-500 dark:text-red-400">7</span>
              </div>
            </div>
          </div>
          <p className="text-[10px] text-slate-400 dark:text-slate-500 leading-relaxed pt-4 border-t border-hyperion-lightBorder dark:border-slate-900 transition-colors">
            Última revisión del análisis de brechas (Gap Analysis) realizada automáticamente.
          </p>
        </div>
      </div>

      {/* Repositorio de Políticas Integrado */}
      <div className="bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/50 rounded-3xl overflow-hidden shadow-sm dark:shadow-2xl transition-colors">
        <div className="p-5 border-b border-hyperion-lightBorder dark:border-slate-800/50 bg-slate-50 dark:bg-slate-900/10 flex justify-between items-center transition-colors">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider flex items-center gap-2 transition-colors">
            <FileText size={16} className="text-blue-500 dark:text-blue-400" /> Matriz de Políticas del SGSI
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 dark:bg-slate-950/50 text-slate-500 dark:text-slate-400 uppercase text-[10px] tracking-widest transition-colors">
              <tr>
                <th className="px-6 py-4">Código / Título</th>
                <th className="px-6 py-4">Versión</th>
                <th className="px-6 py-4">Última Revisión</th>
                <th className="px-6 py-4">Estado</th>
                <th className="px-6 py-4 text-right">Documentación</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hyperion-lightBorder dark:divide-slate-800/40 transition-colors">
              {politicas.map((pol) => (
                <tr key={pol.id} className="hover:bg-blue-500/[0.02] dark:hover:bg-blue-500/[0.01] transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex flex-col">
                      <span className="text-slate-900 dark:text-slate-200 font-medium text-xs md:text-sm transition-colors">{pol.titulo}</span>
                      <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500 transition-colors">{pol.id}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-xs font-mono text-slate-600 dark:text-slate-400 transition-colors">{pol.version}</td>
                  <td className="px-6 py-4 text-xs text-slate-600 dark:text-slate-400 transition-colors">{pol.revisada}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold tracking-wide ${pol.estado === 'Aprobada'
                        ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                        : pol.estado === 'En Revisión'
                          ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
                          : 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20'
                      }`}>
                      {pol.estado}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button className="text-blue-600 dark:text-blue-500 hover:text-blue-500 dark:hover:text-blue-400 text-xs font-medium flex items-center gap-1 ml-auto group transition-colors">
                      Ver Archivo <ArrowUpRight size={14} className="group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}