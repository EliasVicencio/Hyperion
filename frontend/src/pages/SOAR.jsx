import React, { useState } from 'react';
import { Terminal, Cpu, Play, CheckCircle2, ShieldAlert, Zap, Server, Lock, RefreshCw } from 'lucide-react';

export default function SOAR() {
  const [executing, setExecuting] = useState(null);
  const [logsSOAR, setLogsSOAR] = useState([
    { id: 1, action: "AUTO_CONTAINMENT", target: "192.168.1.105", status: "SUCCESS", timestamp: "Hace 5 min", detail: "IP bloqueada en la regla de Firewall Perimetral #882." },
    { id: 2, action: "REVOKE_SESSION", target: "user_compromised@hyperion.io", status: "SUCCESS", timestamp: "Hace 12 min", detail: "Token JWT revocado en Supabase Auth y sesión terminada." }
  ]);

  const playbooks = [
    {
      id: "BLOCK_IP",
      title: "Bloqueo Automático de IP",
      description: "Agrega la IP origen sospechosa a la lista negra del API Gateway y WAF perimetral.",
      category: "Perímetro / Red",
      icon: <Server className="text-blue-400" size={20} />,
      badgeColor: "bg-blue-500/10 text-blue-400 border-blue-500/20"
    },
    {
      id: "ISOLATE_HOST",
      title: "Aislamiento de Endpoint",
      description: "Corta el tráfico no esencial del servidor comprometido manteniendo solo conexión SOC para análisis.",
      category: "Infraestructura",
      icon: <Lock className="text-purple-400" size={20} />,
      badgeColor: "bg-purple-500/10 text-purple-400 border-purple-500/20"
    },
    {
      id: "REVOKE_TOKEN",
      title: "Cierre de Sesión e Invalidación",
      description: "Invalida tokens activos y fuerza la re-autenticación MFA del usuario afectado.",
      category: "Identidad / IAM",
      icon: <Zap className="text-amber-400" size={20} />,
      badgeColor: "bg-amber-500/10 text-amber-400 border-amber-500/20"
    }
  ];

  const runPlaybook = async (playbookId, title) => {
    setExecuting(playbookId);
    
    try {
      const targetSimulado = playbookId === 'REVOKE_TOKEN' ? 'admin_session@hyperion.io' : '10.0.4.12';
      
      const res = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/v1/soar/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: Math.floor(Math.random() * 900) + 100,
          action: playbookId,
          target: targetSimulado
        })
      });

      const data = await res.json();

      const newLog = {
        id: Date.now(),
        action: playbookId,
        target: targetSimulado,
        status: res.ok ? "SUCCESS" : "FAILED",
        timestamp: "Ahora mismo",
        detail: data.message || `Ejecución manual de ${title}`
      };

      setLogsSOAR(prev => [newLog, ...prev]);
    } catch (err) {
      console.error("Error al ejecutar SOAR:", err);
    } finally {
      setExecuting(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Encabezado */}
      <header className="flex justify-between items-end flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-950 dark:text-white tracking-tight flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-purple-600 to-indigo-600 text-white shadow-[0_0_15px_rgba(147,51,234,0.3)]">
              <Cpu size={22} />
            </div>
            Motor de Automatización SOAR
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
            Orquestación de respuesta a incidentes y ejecución de Playbooks de mitigación en tiempo real.
          </p>
        </div>
      </header>

      {/* Grid de Playbooks disponibles */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {playbooks.map((pb) => (
          <div 
            key={pb.id}
            className="bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/60 p-6 rounded-3xl shadow-sm dark:shadow-2xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-all"
          >
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <div className={`p-2.5 rounded-xl border ${pb.badgeColor}`}>
                  {pb.icon}
                </div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 bg-slate-100 dark:bg-slate-900 px-2 py-1 rounded-lg border border-slate-200 dark:border-slate-800">
                  {pb.category}
                </span>
              </div>
              <h3 className="text-lg font-bold text-slate-900 dark:text-white">{pb.title}</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">{pb.description}</p>
            </div>

            <button
              onClick={() => runPlaybook(pb.id, pb.title)}
              disabled={executing === pb.id}
              className="w-full bg-slate-900 hover:bg-slate-800 dark:bg-slate-800/80 dark:hover:bg-slate-700 text-white font-mono text-xs py-2.5 px-4 rounded-xl border border-slate-700/50 flex items-center justify-center gap-2 transition-all shadow-sm active:scale-95 disabled:opacity-50"
            >
              {executing === pb.id ? (
                <>
                  <RefreshCw size={14} className="animate-spin text-purple-400" />
                  <span>EJECUTANDO...</span>
                </>
              ) : (
                <>
                  <Play size={14} className="fill-current text-purple-400" />
                  <span>EJECUTAR PLAYBOOK</span>
                </>
              )}
            </button>
          </div>
        ))}
      </div>

      {/* Terminal de Ejecución / Audit Log del SOAR */}
      <div className="bg-white dark:bg-hyperion-card border border-hyperion-lightBorder dark:border-slate-800/60 rounded-3xl p-6 shadow-sm dark:shadow-2xl space-y-4">
        <div className="flex justify-between items-center border-b border-slate-100 dark:border-slate-800/80 pb-4">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <Terminal size={16} className="text-purple-500" /> Historial de Ejecuciones de Automatización
          </h3>
          <span className="text-xs font-mono text-slate-500">{logsSOAR.length} Acciones Registradas</span>
        </div>

        <div className="space-y-3">
          {logsSOAR.map((log) => (
            <div 
              key={log.id} 
              className="bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 p-4 rounded-2xl flex flex-col md:flex-row justify-between items-start md:items-center gap-3 transition-colors"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="text-purple-600 dark:text-purple-400 font-bold">{log.action}</span>
                  <span className="text-slate-400">→</span>
                  <span className="text-slate-700 dark:text-slate-300 bg-slate-200 dark:bg-slate-800 px-2 py-0.5 rounded text-[11px]">{log.target}</span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400">{log.detail}</p>
              </div>

              <div className="flex items-center gap-3 font-mono text-xs">
                <span className="text-slate-400 text-[11px]">{log.timestamp}</span>
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold border ${
                  log.status === 'SUCCESS' 
                    ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20' 
                    : 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20'
                }`}>
                  <CheckCircle2 size={12} /> {log.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}