import React, { useState, useEffect, useCallback } from 'react';
import { Ticket, Plus, Search, CheckCircle2, Clock, AlertCircle, Trash2, Loader2, RefreshCw } from 'lucide-react';
import { getTickets, createTicket, updateTicket, deleteTicket } from '../api';

export default function Tickets() {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [busqueda, setBusqueda] = useState('');
  const [filtroEstado, setFiltroEstado] = useState('ALL');

  // Modal para nuevo ticket
  const [mostrarModal, setMostrarModal] = useState(false);
  const [nuevoTicket, setNuevoTicket] = useState({ titulo: '', descripcion: '', prioridad: 'MEDIA' });
  const [guardando, setGuardando] = useState(false);

  const cargarTickets = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getTickets();
      // Sanitización de datos por si la API devuelve [] u { data: [] }
      const lista = Array.isArray(data) ? data : (data?.data || data?.items || []);
      setTickets(lista);
    } catch (err) {
      console.error("🚨 Error al cargar tickets:", err);
      setError(err.message || 'Error al conectar con el servicio de tickets.');
      setTickets([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    cargarTickets();
  }, [cargarTickets]);

  const handleCrearTicket = async (e) => {
    e.preventDefault();
    if (!nuevoTicket.titulo.trim()) return;

    setGuardando(true);
    try {
      await createTicket(nuevoTicket);
      setNuevoTicket({ titulo: '', descripcion: '', prioridad: 'MEDIA' });
      setMostrarModal(false);
      await cargarTickets();
    } catch (err) {
      alert("Error al crear ticket: " + err.message);
    } finally {
      setGuardando(false);
    }
  };

  const handleCambiarEstado = async (id, estadoActual) => {
    const nuevoEstado = estadoActual === 'RESUELTO' ? 'ABIERTO' : 'RESUELTO';
    try {
      await updateTicket(id, { estado: nuevoEstado });
      cargarTickets();
    } catch (err) {
      console.error("Error actualizando ticket:", err);
    }
  };

  const handleEliminarTicket = async (id) => {
    if (!window.confirm("¿Confirmas eliminar este ticket?")) return;
    try {
      await deleteTicket(id);
      cargarTickets();
    } catch (err) {
      console.error("Error eliminando ticket:", err);
    }
  };

  // Filtrado de tickets
  const ticketsFiltrados = tickets.filter(t => {
    const coincideTexto = (t.titulo || '').toLowerCase().includes(busqueda.toLowerCase()) ||
                          (t.descripcion || '').toLowerCase().includes(busqueda.toLowerCase());
    const coincideEstado = filtroEstado === 'ALL' || t.estado === filtroEstado;
    return coincideTexto && coincideEstado;
  });

  return (
    <div className="space-y-6">
      {/* Encabezado */}
      <header className="flex justify-between items-end flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-950 dark:text-white tracking-tight flex items-center gap-3">
            <Ticket className="text-blue-500" size={28} /> Gestión de Tickets
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm">Mesa de ayuda e incidentes operativos de Hyperion</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={cargarTickets} 
            className="p-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:bg-slate-50 transition-all"
          >
            <RefreshCw size={18} className={loading ? "animate-spin" : ""} />
          </button>
          <button 
            onClick={() => setMostrarModal(true)}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all shadow-lg shadow-blue-500/20"
          >
            <Plus size={18} /> Nuevo Ticket
          </button>
        </div>
      </header>

      {/* Alerta de error si falla la API */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 p-4 rounded-2xl flex items-center justify-between text-red-600 dark:text-red-400 text-sm">
          <div className="flex items-center gap-3">
            <AlertCircle size={20} />
            <span><strong>Endpoint no encontrado:</strong> {error}</span>
          </div>
          <button onClick={cargarTickets} className="underline text-xs font-mono">Reintentar</button>
        </div>
      )}

      {/* Filtros */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-center bg-white dark:bg-[#0b111e] border border-slate-200 dark:border-slate-800/50 p-4 rounded-2xl">
        <div className="flex gap-2 w-full md:w-auto">
          {['ALL', 'ABIERTO', 'EN_PROCESO', 'RESUELTO'].map((st) => (
            <button
              key={st}
              onClick={() => setFiltroEstado(st)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-all ${
                filtroEstado === st 
                  ? 'bg-blue-600 text-white shadow-sm' 
                  : 'bg-slate-100 dark:bg-slate-900 text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              {st === 'ALL' ? 'TODOS' : st}
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-72">
          <Search className="absolute left-3 top-2.5 text-slate-400" size={16} />
          <input
            type="text"
            placeholder="Buscar por título o contenido..."
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl py-2 pl-9 pr-4 w-full text-xs text-slate-800 dark:text-slate-200 focus:border-blue-500 outline-none"
            value={busqueda}
            onChange={(e) => setBusqueda(e.target.value)}
          />
        </div>
      </div>

      {/* Lista / Tabla de Tickets */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center gap-3 font-mono text-xs">
            <Loader2 className="animate-spin text-blue-500" size={24} />
            Cargando tickets desde el servidor...
          </div>
        ) : ticketsFiltrados.length > 0 ? (
          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {ticketsFiltrados.map((ticket) => (
              <div key={ticket.id} className="p-5 flex items-center justify-between hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition-colors">
                <div className="space-y-1 max-w-xl">
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono font-bold text-slate-400">#{ticket.id}</span>
                    <h3 className="font-semibold text-slate-900 dark:text-white text-base">{ticket.titulo}</h3>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                      ticket.prioridad === 'ALTA' ? 'bg-red-500/10 text-red-500 border border-red-500/20' :
                      ticket.prioridad === 'MEDIA' ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20' :
                      'bg-slate-500/10 text-slate-500'
                    }`}>
                      {ticket.prioridad || 'NORMAL'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-1">{ticket.descripcion || 'Sin descripción.'}</p>
                </div>

                <div className="flex items-center gap-4">
                  <button
                    onClick={() => handleCambiarEstado(ticket.id, ticket.estado)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-all ${
                      ticket.estado === 'RESUELTO'
                        ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30'
                        : 'bg-amber-500/10 text-amber-500 border-amber-500/30'
                    }`}
                  >
                    {ticket.estado === 'RESUELTO' ? <CheckCircle2 size={14} /> : <Clock size={14} />}
                    {ticket.estado || 'ABIERTO'}
                  </button>

                  <button
                    onClick={() => handleEliminarTicket(ticket.id)}
                    className="p-2 text-slate-400 hover:text-red-500 transition-colors rounded-lg hover:bg-red-500/10"
                    title="Eliminar Ticket"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-12 text-center text-slate-400 italic">
            No hay tickets registrados que coincidan con la búsqueda.
          </div>
        )}
      </div>

      {/* Modal para Crear Ticket */}
      {mostrarModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 w-full max-w-md shadow-2xl space-y-4">
            <h2 className="text-xl font-bold text-slate-900 dark:text-white">Crear Nuevo Ticket</h2>
            <form onSubmit={handleCrearTicket} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-500 mb-1">Título</label>
                <input
                  type="text"
                  required
                  placeholder="Ej: Fallo en autenticación JWT"
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-sm outline-none focus:border-blue-500 text-slate-900 dark:text-white"
                  value={nuevoTicket.titulo}
                  onChange={(e) => setNuevoTicket({ ...nuevoTicket, titulo: e.target.value })}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-500 mb-1">Descripción</label>
                <textarea
                  rows="3"
                  placeholder="Detalles del problema..."
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-sm outline-none focus:border-blue-500 text-slate-900 dark:text-white resize-none"
                  value={nuevoTicket.descripcion}
                  onChange={(e) => setNuevoTicket({ ...nuevoTicket, descripcion: e.target.value })}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-500 mb-1">Prioridad</label>
                <select
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-2.5 text-sm outline-none focus:border-blue-500 text-slate-900 dark:text-white"
                  value={nuevoTicket.prioridad}
                  onChange={(e) => setNuevoTicket({ ...nuevoTicket, prioridad: e.target.value })}
                >
                  <option value="BAJA">Baja</option>
                  <option value="MEDIA">Media</option>
                  <option value="ALTA">Alta</option>
                  <option value="CRITICA">Crítica</option>
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setMostrarModal(false)}
                  className="px-4 py-2 rounded-xl text-sm font-medium text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={guardando}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-xl text-sm font-semibold transition-all flex items-center gap-2"
                >
                  {guardando && <Loader2 className="animate-spin" size={16} />}
                  Guardar Ticket
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}