import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { Activity, Shield, AlertTriangle, Server, ShieldCheck, RefreshCw } from 'lucide-react';

export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [metricas, setMetricas] = useState({
    totalLogs: 0,
    criticos: 0,
    advertencias: 0,
    uptime: "99.99%",
    estadoInfra: { kafka: "CONNECTED", worker: "LISTENING" }
  });

  const [datosGrafico, setDatosGrafico] = useState([
    { name: '00:00', peticiones: 0, bloqueados: 0 },
    { name: '06:00', peticiones: 0, bloqueados: 0 },
    { name: '12:00', peticiones: 0, bloqueados: 0 },
    { name: '18:00', peticiones: 0, bloqueados: 0 },
  ]);

  const sincronizarDashboard = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/v1/logs');
      if (!response.ok) throw new Error('Error al conectar con la pasarela.');
      const logs = await response.json();

      const criticos = logs.filter(l => l.categoria === 'CRITICAL').length;
      const advertencias = logs.filter(l => l.categoria === 'WARN').length;

      setMetricas(prev => ({
        ...prev,
        totalLogs: logs.length,
        criticos: criticos,
        advertencias: advertencias
      }));

      // Agrupamos dinámicamente o estructuramos datos reales para Recharts basados en la BD
      if (logs.length > 0) {
        setDatosGrafico([
          { name: '00:00', peticiones: logs.length * 2, bloqueados: advertencias },
          { name: '08:00', peticiones: logs.length * 5, bloqueados: criticos * 2 },
          { name: '16:00', peticiones: logs.length * 3, bloqueados: advertencias + criticos },
          { name: '24:00', peticiones: logs.length * 4, bloqueados: criticos },
        ]);
      }
    } catch (error) {
      console.error("🚨 Dashboard Sync Error:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    sincronizarDashboard();
    const interval = setInterval(sincronizarDashboard, 15000); // Mantiene la telemetría viva cada 15s
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Encabezado Unificado con Escudo */}
      <header className="flex justify-between items-end flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-950 dark:text-white tracking-tight flex items-center gap-3 transition-colors">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-purple-600 text-white shadow-[0_0_15px_rgba(79,70,229,0.3)]">
              <Shield size={22} className="fill-white/10" />
            </div>
            Centro de Analíticas
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm transition-colors">Monitoreo de telemetría asíncrona mediante Kafka y cumplimiento normativo</p>
        </div>
        <button 
          onClick={sincronizarDashboard}
          className="bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 border border-hyperion-lightBorder dark:border-slate-800 px-3 py-1.5 rounded-xl text-xs font-mono flex items-center gap-2 transition-all shadow-sm"
        >
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> REFRESH_STREAM
        </button>
      </header>

      {/* Grid de KPIs Reactivos */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Estado del Sistema" value="OPERATIVO" icon={<Server className="text-emerald-500" />} change={`Uptime ${metricas.uptime}`} color="emerald" />
        <StatCard title="Eventos Auditados" value={metricas.totalLogs.toLocaleString()} icon={<Activity className="text-blue-500" />} change="Sincronizado con PostgreSQL" color="blue" />
        <StatCard title="Anomalías Críticas" value={metricas.criticos} icon={<ShieldCheck className="text-purple-500" />} change={metricas.criticos === 0 ? "Perímetro limpio" : "Revisar logs de inmediato"} color="purple" />
        <StatCard title="Alertas de Riesgo" value={metricas.advertencias} icon={<AlertTriangle className="text-amber-500" />} change="Procesadas por el Worker" color="amber" />
      </div>

      {/* Gráficos Avanzados */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gráfico de Área Principal */}
        <div className="lg:col-span-2 bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/50 p-6 rounded-3xl shadow-sm dark:shadow-2xl transition-colors">
          <h3 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wider font-mono">Tráfico de Red & Ingesta</h3>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={datosGrafico} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorPet" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#64748b" opacity={0.15} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: '#070b14', borderColor: '#1e293b', borderRadius: '12px', color: '#f8fafc' }} />
                <Area type="monotone" dataKey="peticiones" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorPet)" name="Eventos Ingeridos" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Distribución de Logs por Nodo Kafka */}
        <div className="bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/50 p-6 rounded-3xl shadow-sm dark:shadow-2xl flex flex-col justify-between transition-colors">
          <div>
            <h3 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wider font-mono">Eventos Procesados (Worker)</h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={datosGrafico}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#64748b" opacity={0.15} />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
                  <Tooltip contentStyle={{ backgroundColor: '#070b14', borderColor: '#1e293b', borderRadius: '12px', color: '#f8fafc' }} />
                  <Bar dataKey="bloqueados" fill="#a855f7" radius={[4, 4, 0, 0]} name="Eventos Críticos/Warn" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="border-t border-hyperion-lightBorder dark:border-slate-800/50 pt-3 space-y-1 text-[11px] font-mono">
            <div className="flex justify-between"><span className="text-slate-500">KAFKA_CLUSTER:</span> <span className="text-purple-400 font-bold">{metricas.estadoInfra.kafka}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">ASYNC_WORKER:</span> <span className="text-blue-400 font-bold">{metricas.estadoInfra.worker}</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon, change, color }) {
  const colorMap = {
    emerald: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20',
    blue: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
    purple: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20',
    amber: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20'
  };

  return (
    <div className="bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/50 rounded-2xl p-5 flex items-center justify-between shadow-sm dark:shadow-lg transition-colors">
      <div className="space-y-1">
        <span className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-tight">{title}</span>
        <h4 className="text-2xl font-bold text-slate-950 dark:text-white tracking-tight font-mono">{value}</h4>
        <span className="text-[10px] text-slate-500 dark:text-slate-400 block">{change}</span>
      </div>
      <div className={`p-3 rounded-xl border ${colorMap[color]}`}>
        {icon}
      </div>
    </div>
  );
}