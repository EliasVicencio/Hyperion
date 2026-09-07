import React, { useEffect, useState } from 'react';
import { apiGet, apiPost, apiPatch, apiDelete } from '../api';

export default function Tickets() {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [newTicketTitle, setNewTicketTitle] = useState('');
  const [newTicketDescription, setNewTicketDescription] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Cargar tickets al montar el componente
  const fetchTickets = async () => {
    try {
      setLoading(true);
      // Se pasa '/tickets' directamente sin '/api/v1'
      const data = await apiGet('/tickets');
      setTickets(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      console.error('Error al obtener los tickets:', err);
      setError('No se pudieron cargar los tickets desde el servidor.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTickets();
  }, []);

  // Crear un nuevo ticket
  const handleCreateTicket = async (e) => {
    e.preventDefault();
    if (!newTicketTitle.trim()) return;

    try {
      setIsSubmitting(true);
      const payload = {
        title: newTicketTitle,
        description: newTicketDescription,
        status: 'open',
      };

      const createdTicket = await apiPost('/tickets', payload);
      setTickets((prev) => [...prev, createdTicket]);
      setNewTicketTitle('');
      setNewTicketDescription('');
    } catch (err) {
      console.error('Error al crear ticket:', err);
      alert('Error al crear el ticket');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Actualizar estado de ticket
  const handleToggleStatus = async (ticket) => {
    try {
      const updatedStatus = ticket.status === 'open' ? 'closed' : 'open';
      const updated = await apiPatch(`/tickets/${ticket.id || ticket._id}`, {
        status: updatedStatus,
      });

      setTickets((prev) =>
        prev.map((item) =>
          (item.id || item._id) === (ticket.id || ticket._id) ? updated : item
        )
      );
    } catch (err) {
      console.error('Error al actualizar estado:', err);
      alert('No se pudo cambiar el estado');
    }
  };

  // Eliminar ticket
  const handleDeleteTicket = async (id) => {
    if (!window.confirm('¿Seguro que deseas eliminar este ticket?')) return;

    try {
      await apiDelete(`/tickets/${id}`);
      setTickets((prev) => prev.filter((item) => (item.id || item._id) !== id));
    } catch (err) {
      console.error('Error al eliminar ticket:', err);
      alert('No se pudo eliminar el ticket');
    }
  };

  return (
    <div style={{ padding: '24px', maxWidth: '800px', margin: '0 auto' }}>
      <h1>Módulo de Tickets</h1>

      {/* Formulario de creación */}
      <form
        onSubmit={handleCreateTicket}
        style={{
          marginBottom: '32px',
          padding: '16px',
          border: '1px solid #ccc',
          borderRadius: '8px',
        }}
      >
        <h3>Crear Nuevo Ticket</h3>
        <div style={{ marginBottom: '12px' }}>
          <input
            type="text"
            placeholder="Título del ticket"
            value={newTicketTitle}
            onChange={(e) => setNewTicketTitle(e.target.value)}
            style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
            required
          />
        </div>
        <div style={{ marginBottom: '12px' }}>
          <textarea
            placeholder="Descripción detallada"
            value={newTicketDescription}
            onChange={(e) => setNewTicketDescription(e.target.value)}
            style={{
              width: '100%',
              padding: '8px',
              height: '80px',
              boxSizing: 'border-box',
            }}
          />
        </div>
        <button type="submit" disabled={isSubmitting}>
          {isSubmitting ? 'Guardando...' : 'Crear Ticket'}
        </button>
      </form>

      {/* Vista de estados */}
      {loading && <p>Cargando lista de tickets...</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}

      {/* Lista de tickets */}
      {!loading && !error && (
        <div>
          <h3>Listado de Tickets ({tickets.length})</h3>
          {tickets.length === 0 ? (
            <p>No existen tickets registrados en la plataforma.</p>
          ) : (
            <ul style={{ listStyle: 'none', padding: 0 }}>
              {tickets.map((ticket) => {
                const ticketId = ticket.id || ticket._id;
                return (
                  <li
                    key={ticketId}
                    style={{
                      padding: '12px',
                      border: '1px solid #ddd',
                      marginBottom: '8px',
                      borderRadius: '4px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <div>
                      <strong>{ticket.title || 'Sin Título'}</strong>
                      <p style={{ margin: '4px 0 0 0', color: '#666' }}>
                        {ticket.description || 'Sin descripción'}
                      </p>
                      <small>Estado: {ticket.status || 'desconocido'}</small>
                    </div>

                    <div>
                      <button
                        onClick={() => handleToggleStatus(ticket)}
                        style={{ marginRight: '8px' }}
                      >
                        Cambiar Estado
                      </button>
                      <button
                        onClick={() => handleDeleteTicket(ticketId)}
                        style={{ backgroundColor: '#ff4d4f', color: '#fff' }}
                      >
                        Eliminar
                      </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}