import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { Activity, ShieldCheck, AlertTriangle, Server } from 'lucide-react';

const datosTrafico = [
  { name: '00:00', peticiones: 2400, bloqueados: 400 },
  { name: '04:00', peticiones: 1398, bloqueados: 210 },
  { name: '08:00', peticiones: 9800, bloqueados: 1290 },
  { name: '12:00', peticiones: 3908, bloqueados: 850 },
  { name: '16:00', peticiones: 4800, bloqueados: 660 },
  { name: '20:00', peticiones: 3800, bloqueados: 490 },
];

export default function Dashboard() {
  return (
    <div className="space-y-6">
      {/* Encabezado */}
      <header>
        <h1 className="text-3xl font-bold text-slate-950 dark:text-white tracking-tight transition-colors">Centro de Analíticas</h1>
        <p className="text-slate-500 dark:text-slate-400 text-sm transition-colors">Monitoreo de telemetría y cumplimiento normativo en tiempo real</p>
      </header>

      {/* Grid de KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard title="Estado del Sistema" value="OPERATIVO" icon={<Server className="text-emerald-500 dark:text-emerald-400" />} change="uptime 99.98%" color="emerald" />
        <StatCard title="Eventos Auditados" value="12,482" icon={<Activity className="text-blue-500 dark:text-blue-400" />} change="+12% en la última hora" color="blue" />
        <StatCard title="Alertas Críticas" value="0" icon={<ShieldCheck className="text-purple-500 dark:text-purple-400" />} change="Todo en orden" color="purple" />
        <StatCard title="Intentos Bloqueados" value="342" icon={<AlertTriangle className="text-amber-500 dark:text-amber-400" />} change="Mitigación activa" color="amber" />
      </div>

      {/* Gráficos Avanzados */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gráfico de Área Principal */}
        <div className="lg:col-span-2 bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/50 p-6 rounded-3xl shadow-sm dark:shadow-2xl transition-colors">
          <h3 className="text-sm font-semibold text-slate-400 dark:text-slate-400 mb-4 uppercase tracking-wider">Tráfico de Red & Mitigación</h3>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={datosTrafico} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorPet" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#64748b" opacity={0.15} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '12px', color: '#0f172a' }} className="dark:[&>.recharts-default-tooltip]:!bg-[#070b14] dark:[&>.recharts-default-tooltip]:!border-[#1e293b] dark:[&>.recharts-default-tooltip]:!text-[#f8fafc]" />
                <Area type="monotone" dataKey="peticiones" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorPet)" name="Peticiones" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Distribución de Logs de Control */}
        <div className="bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/50 p-6 rounded-3xl shadow-sm dark:shadow-2xl flex flex-col justify-between transition-colors">
          <div>
            <h3 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wider">Eventos por Nodo</h3>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={datosTrafico}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#64748b" opacity={0.15} />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
                  <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '12px', color: '#0f172a' }} className="dark:[&>.recharts-default-tooltip]:!bg-[#070b14] dark:[&>.recharts-default-tooltip]:!border-[#1e293b] dark:[&>.recharts-default-tooltip]:!text-[#f8fafc]" />
                  <Bar dataKey="bloqueados" fill="#a855f7" radius={[4, 4, 0, 0]} name="Bloqueos" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          <p className="text-[11px] text-slate-400 dark:text-slate-500 text-center border-t border-hyperion-lightBorder dark:border-slate-800/50 pt-3 transition-colors">
            Sincronizado con Gateway central hace unos instantes.
          </p>
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
      <div className="space-y-2">
        <span className="text-xs font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-tight transition-colors">{" "}{title}</span>
        <h4 className="text-2xl font-bold text-slate-950 dark:text-white tracking-tight transition-colors">{" "}{value}</h4>
        <span className="text-[10px] text-slate-500 dark:text-slate-400 block transition-colors">{" "}{change}</span>
      </div>
      <div className={`p-3 rounded-xl border ${colorMap[color]}`}>
        {icon}
      </div>
    </div>
  );
}