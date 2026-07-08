import React, { useState, useEffect } from 'react';
import { Database, ShieldAlert, Users, Server, Layers, AlertTriangle, TrendingUp, CheckCircle, WifiOff } from 'lucide-react';
import { apiGet } from '../api';

export default function ActivosRiesgos() {
  const [activos, setActivos] = useState([]);
  const [riesgos, setRiesgos] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isOffline, setIsOffline] = useState(false);

  const cargarDatos = async () => {
    try {
<<<<<<< HEAD
      const res = await fetch('/api/v1/riesgos/dashboard');
      if (!res.ok) throw new Error("Error de conexión con la API Gateway");
      
=======
      const res = await apiGet('/api/v1/riesgos/dashboard');
      if (!res.ok) throw new Error("Error en la API");
>>>>>>> 4ab778d (Refactor backend en routers, JWT + RBAC, WebSocket auto-reconnect, CI/CD)
      const data = await res.json();
      const listaActivos = data.activos || [];
      const listaRiesgos = data.matriz_riesgos || [];

      setActivos(listaActivos);
      setRiesgos(listaRiesgos);
      setIsOffline(false);

      // 💾 Guardamos respaldo local inmutable para contingencias
      localStorage.setItem('hyperion_backup_activos', JSON.stringify(listaActivos));
      localStorage.setItem('hyperion_backup_riesgos', JSON.stringify(listaRiesgos));

    } catch (e) {
      console.warn("⚠️ Detectada caída del backend. Activando persistencia local...");
      setIsOffline(true);

      // 🔄 Recuperación elástica de datos (Respaldo local)
      const respaldoActivos = localStorage.getItem('hyperion_backup_activos');
      const respaldoRiesgos = localStorage.getItem('hyperion_backup_riesgos');

      if (respaldoActivos && respaldoRiesgos) {
        // Mapeamos los activos para forzar el estado "CRÍTICO" debido a la caída de la infraestructura
        const activosDegradados = JSON.parse(respaldoActivos).map(activo => ({
          ...activo,
          estado: 'CRÍTICO' 
        }));
        setActivos(activosDegradados);
        setRiesgos(JSON.parse(respaldoRiesgos));
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    cargarDatos();
  }, []);

  // Cuadrícula analítica del Mapa de Calor (5x5) basado en ISO 27005
  const celdasMapaCalor = [
    { p: 5, i: 1, label: 'Bajo', color: 'bg-amber-500/20 text-amber-500' },
    { p: 5, i: 2, label: 'Medio', color: 'bg-amber-500/40 text-amber-600' },
    { p: 5, i: 3, label: 'Alto', color: 'bg-red-500/60 text-white' },
    { p: 5, i: 4, label: 'Crítico', color: 'bg-red-600 text-white' },
    { p: 5, i: 5, label: 'Crítico', color: 'bg-red-700 text-white' },

    { p: 4, i: 1, label: 'Bajo', color: 'bg-emerald-500/40 text-emerald-600' },
    { p: 4, i: 2, label: 'Medio', color: 'bg-amber-500/20 text-amber-500' },
    { p: 4, i: 3, label: 'Alto', color: 'bg-amber-500/60 text-amber-700' },
    { p: 4, i: 4, label: 'Alto', color: 'bg-red-500/60 text-white' },
    { p: 4, i: 5, label: 'Crítico', color: 'bg-red-600 text-white' },

    { p: 3, i: 1, label: 'Bajo', color: 'bg-emerald-500/20 text-emerald-500' },
    { p: 3, i: 2, label: 'Bajo', color: 'bg-emerald-500/40 text-emerald-600' },
    { p: 3, i: 3, label: 'Medio', color: 'bg-amber-500/20 text-amber-500' },
    { p: 3, i: 4, label: 'Alto', color: 'bg-amber-500/60 text-amber-700' },
    { p: 3, i: 5, label: 'Alto', color: 'bg-red-500/60 text-white' },

    { p: 2, i: 1, label: 'Bajo', color: 'bg-emerald-500/20 text-emerald-500' },
    { p: 2, i: 2, label: 'Bajo', color: 'bg-emerald-500/20 text-emerald-500' },
    { p: 2, i: 3, label: 'Bajo', color: 'bg-emerald-500/40 text-emerald-600' },
    { p: 2, i: 4, label: 'Medio', color: 'bg-amber-500/20 text-amber-500' },
    { p: 2, i: 5, label: 'Alto', color: 'bg-amber-500/60 text-amber-700' },

    { p: 1, i: 1, label: 'Bajo', color: 'bg-emerald-500/10 text-emerald-400' },
    { p: 1, i: 2, label: 'Bajo', color: 'bg-emerald-500/20 text-emerald-500' },
    { p: 1, i: 3, label: 'Bajo', color: 'bg-emerald-500/20 text-emerald-500' },
    { p: 1, i: 4, label: 'Bajo', color: 'bg-emerald-500/40 text-emerald-600' },
    { p: 1, i: 5, label: 'Medio', color: 'bg-amber-500/20 text-amber-500' },
  ];

  const getRiesgoBadge = (nivel) => {
    if (nivel >= 15) return "bg-red-500/10 text-red-500 border-red-500/20";
    if (nivel >= 8) return "bg-amber-500/10 text-amber-500 border-amber-500/20";
    return "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";
  };

  if (loading) return <div className="p-8 text-center font-mono text-xs text-slate-400">CARGANDO_INVENTARIO_Y_RIESGOS_ISO...</div>;

  return (
    <div className="space-y-6 text-slate-800 dark:text-slate-300">
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-600 to-purple-600 text-white shadow-md">
              <Layers size={22} />
            </div>
            Inventario de Activos y Matriz de Riesgos
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
            Mapeo y evaluación automatizada bajo directrices de las normas <b>ISO/IEC 27001:2022 (A.5)</b> e <b>ISO 27005</b>.
          </p>
        </div>

        {/* Alerta Perimetral de estado Offline */}
        {isOffline && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl border border-red-500/20 bg-red-500/10 text-red-400 font-mono text-xs animate-pulse">
            <WifiOff size={14} />
            <span>MODO_CONTINGENCIA: CAÍDA_DE_INFRAESTRUCTURA_DETECTADA</span>
          </div>
        )}
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
                  activo.estado === 'SALUDABLE' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-500 border-red-500/30 animate-pulse'
                }`}>
                  {activo.estado}
                </span>
              </div>
              
              <div className="pt-2 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span className="flex items-center gap-1"><Users size={12}/> {activo.responsable || "SRE-Team"}</span>
                <span>Crit: <b className="text-slate-600 dark:text-slate-200">{activo.criticidad}</b></span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* DISEÑO MAPA DE CALOR INTERACTIVO (ISO 27005) */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-3">
          <h2 className="text-sm font-bold font-mono tracking-wider text-slate-400 uppercase">🗺️ MAPA DE CALOR CRIPTOGRÁFICO DE RIESGOS</h2>
          <div className="p-6 bg-white dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800/80 rounded-2xl shadow-sm backdrop-blur-sm flex gap-4">
            
            {/* Eje Y: Probabilidad */}
            <div className="flex flex-col justify-between text-[10px] font-mono text-slate-400 pb-8 pt-4 uppercase tracking-widest font-bold w-4 text-center">
              <span>5</span><span>4</span><span>3</span><span>2</span><span>1</span>
            </div>

            <div className="flex-1 space-y-4">
              {/* Cuadrícula 5x5 */}
              <div className="grid grid-cols-5 gap-1.5 aspect-square max-h-[360px] w-full">
                {celdasMapaCalor.map((celda, idx) => {
                  const amenazasEnCelda = riesgos.filter(r => r.probabilidad === celda.p && r.impacto === celda.i);
                  return (
                    <div 
                      key={idx} 
                      className={`rounded-xl p-1 flex flex-col items-center justify-center border border-slate-200/10 transition-all font-mono text-center relative group ${celda.color}`}
                    >
                      <span className="text-[9px] font-extrabold opacity-40">{celda.label}</span>
                      {amenazasEnCelda.length > 0 && (
                        <span className="mt-1 bg-slate-950 text-white dark:bg-white dark:text-slate-950 text-[10px] font-bold w-5 h-5 rounded-full flex items-center justify-center shadow-lg border border-white/20 animate-bounce">
                          {amenazasEnCelda.length}
                        </span>
                      )}
                      
                      {/* Tooltip flotante con detalles */}
                      {amenazasEnCelda.length > 0 && (
                        <div className="hidden group-hover:block absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 w-48 bg-slate-950 text-white text-[10px] rounded-lg p-2 z-50 shadow-xl border border-slate-800">
                          <p className="font-bold border-b border-slate-800 pb-1 mb-1">Impacto: {celda.i} | Prob: {celda.p}</p>
                          {amenazasEnCelda.map(a => (
                            <p key={a.id} className="truncate">• {a.activo_name}: {a.amenaza}</p>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
              {/* Eje X: Impacto */}
              <div className="grid grid-cols-5 text-center text-[10px] font-mono text-slate-400 uppercase tracking-widest font-bold px-1">
                <span>1</span><span>2</span><span>3</span><span>4</span><span>5</span>
              </div>
            </div>
          </div>
        </div>

        {/* Panel lateral informativo del mapa de calor */}
        <div className="space-y-3 flex flex-col justify-end">
          <div className="p-5 bg-slate-50 dark:bg-slate-950/40 border border-slate-200 dark:border-slate-800/60 rounded-2xl space-y-3 h-full flex flex-col justify-center">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-indigo-500">Distribución de Criticidad</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Las amenazas se distribuyen automáticamente cruzando el nivel de probabilidad de ocurrencia e impacto de degradación de activos.
            </p>
            <div className="space-y-2 pt-2 text-[11px] font-mono">
              <div className="flex items-center gap-2"><span className="w-3 h-3 bg-red-600 rounded-md"></span><span>Riesgo Crítico (Zona No Aceptable)</span></div>
              <div className="flex items-center gap-2"><span className="w-3 h-3 bg-amber-500/60 rounded-md"></span><span>Riesgo Alto / Medio (Mitigación Requerida)</span></div>
              <div className="flex items-center gap-2"><span className="w-3 h-3 bg-emerald-500/40 rounded-md"></span><span>Riesgo Bajo (Aceptable bajo monitoreo)</span></div>
            </div>
          </div>
        </div>
      </section>

      {/* SECCIÓN 3: MATRIZ DETALLADA */}
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
                      <span className={`px-2.5 py-1 rounded border font-extrabold text-[11px] ${getRiesgoBadge(riesgo.nivel || (riesgo.probabilidad * riesgo.impacto))}`}>
                        {riesgo.nivel || (riesgo.probabilidad * riesgo.impacto)} / 25
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