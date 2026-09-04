import React, { useState, useEffect } from 'react';
import { AlertTriangle, ShieldAlert, CheckCircle, UserCheck, Play, RefreshCw } from 'lucide-react';
import { apiGet } from '../api';

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const res = await apiGet('/api/v1/incidents');
      if (res.ok) {
        const data = await res.json();
        setIncidents(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error("Error al cargar incidentes:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleMitigate = async (id, action, target) => {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/v1/soar/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident_id: id, action, target })
      });
      if (res.ok) {
        alert(`Playbook ejecutado: ${action} sobre ${target}`);
        fetchIncidents();
      }
    } catch (err) {
      console.error("Error ejecutando Playbook:", err);
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="text-red-500" /> Triaje de Incidentes L1 / L2
          </h1>
          <p className="text-slate-400 text-sm">Gestión de alertas en tiempo real y mitigar con Playbooks SOAR</p>
        </div>
        <button onClick={fetchIncidents} className="bg-slate-800 text-slate-300 px-3 py-1.5 rounded-xl border border-slate-700 flex items-center gap-2 text-xs font-mono">
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} /> REFRESH
        </button>
      </header>

      <div className="grid grid-cols-1 gap-4">
        {incidents.map((inc) => (
          <div key={inc.id} className="bg-slate-900 border border-slate-800 p-5 rounded-2xl flex flex-col md:flex-row justify-between gap-4 items-start md:items-center">
            <div className="space-y-1">
              <div className="flex items-center gap-3">
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono ${inc.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'}`}>
                  {inc.severity}
                </span>
                <span className="text-xs font-mono text-slate-500">INC-{inc.id}</span>
                <span className="text-xs font-mono text-slate-400">IP: {inc.source_ip}</span>
              </div>
              <h3 className="text-lg font-semibold text-white">{inc.title}</h3>
              <p className="text-slate-400 text-sm">{inc.description}</p>
            </div>

            <div className="flex flex-wrap gap-2 items-center">
              <button 
                onClick={() => handleMitigate(inc.id, 'BLOCK_IP', inc.source_ip)}
                className="bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 px-3 py-1.5 rounded-xl text-xs font-mono flex items-center gap-1.5 transition-all"
              >
                <Play size={12} /> Bloquear IP
              </button>
              <button 
                onClick={() => handleMitigate(inc.id, 'ISOLATE_HOST', inc.source_ip)}
                className="bg-purple-600/20 hover:bg-purple-600/30 text-purple-400 border border-purple-500/30 px-3 py-1.5 rounded-xl text-xs font-mono flex items-center gap-1.5 transition-all"
              >
                <Play size={12} /> Aislar Host
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}