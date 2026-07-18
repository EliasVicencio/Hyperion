import React, { useState, useEffect } from 'react';
import { Ticket, Plus, Loader2, AlertCircle, CheckCircle2, Circle } from 'lucide-react';
import { apiGet, apiPost, apiPatch } from '../api';

const PRIORIDAD_ESTILO = {
  CRITICA: 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-900/30',
  ALTA: 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/40 border-orange-200 dark:border-orange-900/30',
  MEDIA: 'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-900/30',
  BAJA: 'text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-900/30',
};

export default function Tickets() {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [titulo, setTitulo] = useState('');
  const [descripcion, setDescripcion] = useState('');
  const [prioridad, setPrioridad] = useState('MEDIA');
  const [creando, setCreando] = useState(false);

  const cargarTickets = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiGet('/api/v1/tickets');
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'No se pudieron cargar los tickets.');
      setTickets(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { cargarTickets(); }, []);

  const crearTicket = async (e) => {
    e.preventDefault();
    if (!titulo.trim()) return;
    setCreando(true);
    setError(null);
    try {
      const response = await apiPost('/api/v1/tickets', { titulo, descripcion, prioridad });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'No se pudo crear el ticket.');
      setTickets(prev => [data, ...prev]);
      setTitulo('');
      setDescripcion('');
      setPrioridad('MEDIA');
    } catch (err) {
      setError(err.message);
    } finally {
      setCreando(false);
    }
  };

  const alternarEstado = async (ticket) => {
    const nuevoEstado = ticket.estado === 'ABIERTO' ? 'CERRADO' : 'ABIERTO';
    // Optimista: actualizamos en pantalla de inmediato, revertimos si falla
    setTickets(prev => prev.map(t => t.id === ticket.id ? { ...t, estado: nuevoEstado } : t));
    try {
      const response = await apiPatch(`/api/v1/tickets/${ticket.id}`, { estado: nuevoEstado });
      if (!response.ok) throw new Error();
    } catch {
      setTickets(prev => prev.map(t => t.id === ticket.id ? { ...t, estado: ticket.estado } : t));
    }
  };

  return (
    <div className="space-y-6 text-slate-800 dark:text-slate-200">
      <header>
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 text-white">
            <Ticket size={22} />
          </div>
          Tickets de Soporte
        </h1>
        <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">Incidentes y solicitudes, con notificación automática a Slack</p>
      </header>

      {/* Formulario de creación */}
      <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 p-6 rounded-2xl shadow-sm dark:shadow-xl">
        <form onSubmit={crearTicket} className="space-y-3">
          <input
            type="text"
            value={titulo}
            onChange={(e) => setTitulo(e.target.value)}
            placeholder="Título del ticket"
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-800 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-blue-500/50"
          />
          <textarea
            value={descripcion}
            onChange={(e) => setDescripcion(e.target.value)}
            placeholder="Descripción (opcional)"
            rows={2}
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-800 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-blue-500/50 resize-none"
          />
          <div className="flex gap-3">
            <select
              value={prioridad}
              onChange={(e) => setPrioridad(e.target.value)}
              className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-3 py-2.5 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:border-blue-500/50"
            >
              <option value="BAJA">Baja</option>
              <option value="MEDIA">Media</option>
              <option value="ALTA">Alta</option>
              <option value="CRITICA">Crítica</option>
            </select>
            <button
              type="submit"
              disabled={creando || !titulo.trim()}
              className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold rounded-xl text-sm flex items-center justify-center gap-2 transition-all"
            >
              {creando ? <Loader2 size={16} className="animate-spin" /> : <Plus size={16} />}
              Crear Ticket
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 p-3 rounded-xl text-red-500 dark:text-red-400 text-xs flex items-center gap-2">
          <AlertCircle size={16} /> {error}
        </div>
      )}

      {/* Lista de tickets */}
      <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 p-6 rounded-2xl shadow-sm dark:shadow-xl">
        <h3 className="text-xs font-bold text-slate-500 dark:text-slate-400 mb-4 uppercase tracking-wider">
          Tickets ({tickets.length})
        </h3>

        {loading ? (
          <div className="text-center py-8 text-slate-400 dark:text-slate-600 text-sm">Cargando...</div>
        ) : tickets.length === 0 ? (
          <div className="text-center py-8 text-slate-400 dark:text-slate-600 text-sm">Sin tickets todavía.</div>
        ) : (
          <div className="space-y-3">
            {tickets.map(ticket => (
              <div
                key={ticket.id}
                className={`border rounded-xl p-4 flex items-center justify-between gap-4 transition-colors ${
                  ticket.estado === 'CERRADO'
                    ? 'bg-slate-50/50 dark:bg-slate-950/40 border-slate-100 dark:border-slate-900 opacity-60'
                    : 'bg-slate-50/50 dark:bg-slate-950/40 border-slate-100 dark:border-slate-900'
                }`}
              >
                <button onClick={() => alternarEstado(ticket)} className="shrink-0" title="Cambiar estado">
                  {ticket.estado === 'CERRADO'
                    ? <CheckCircle2 size={20} className="text-emerald-500" />
                    : <Circle size={20} className="text-slate-300 dark:text-slate-700 hover:text-blue-500 transition-colors" />}
                </button>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className={`text-sm font-semibold ${ticket.estado === 'CERRADO' ? 'line-through text-slate-400 dark:text-slate-600' : 'text-slate-800 dark:text-slate-200'}`}>
                      {ticket.titulo}
                    </p>
                    <span className="text-[10px] text-slate-400 dark:text-slate-600 font-mono">#{ticket.id}</span>
                    {ticket.origen === 'API_EXTERNA' && (
                      <span className="text-[9px] bg-slate-100 dark:bg-slate-900 text-slate-500 dark:text-slate-400 px-1.5 py-0.5 rounded font-mono">EXTERNO</span>
                    )}
                  </div>
                  {ticket.descripcion && (
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{ticket.descripcion}</p>
                  )}
                  <p className="text-[10px] text-slate-400 dark:text-slate-600 mt-1 font-mono">{ticket.creado_por} · {ticket.created_at}</p>
                </div>

                <span className={`text-[10px] font-extrabold px-2 py-0.5 rounded border tracking-wide shrink-0 ${PRIORIDAD_ESTILO[ticket.prioridad] || PRIORIDAD_ESTILO.MEDIA}`}>
                  {ticket.prioridad}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}