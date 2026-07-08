import React, { useState } from 'react';
import { X, UserPlus, Shield, Loader2 } from 'lucide-react';
import { apiPost } from '../api';

export default function ModalCrearOperador({ isOpen, onClose, onUserCreated }) {
  // --- Estados del Formulario ---
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    password: '',
    role: 'Operador perimetral' // Rol por defecto adaptado al SGSI
  });
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await apiPost('/api/v1/register', {
        email: formData.email,
        password: formData.password,
        nombre: formData.fullName,
        role: formData.role
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Error al dar de alta al operador en el perímetro.');
      }

      // Notificar al componente padre para que refresque la tabla de usuarios
      if (onUserCreated) onUserCreated(data);
      
      // Limpiar formulario y cerrar modal
      setFormData({ fullName: '', email: '', password: '', role: 'Operador perimetral' });
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-md animate-fade-in p-4">
      
      {/* Contenedor del Modal (Paleta Hyperion Core) */}
      <div className="w-full max-w-md bg-[#050810] border border-slate-900 text-slate-200 p-6 rounded-2xl shadow-2xl shadow-black/80 flex flex-col relative animate-scale-in">
        
        {/* Botón Cerrar Esquina */}
        <button 
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-500 hover:text-white p-1.5 rounded-lg bg-slate-900/50 hover:bg-slate-900 border border-transparent hover:border-slate-800/60 transition-all"
        >
          <X size={16} />
        </button>

        {/* Encabezado */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-9 h-9 bg-blue-600/10 border border-blue-500/20 rounded-xl flex items-center justify-center text-blue-400 shadow-[0_0_15px_rgba(59,130,246,0.1)]">
            <UserPlus size={18} />
          </div>
          <div>
            <h3 className="text-base font-bold text-white tracking-wide">Crear Nuevo Operador</h3>
            <p className="text-xs text-slate-500">Añadir credenciales autorizadas al SGSI</p>
          </div>
        </div>

        {/* Feedback de Error */}
        {error && (
          <div className="mb-4 bg-red-500/10 border border-red-500/20 p-3 rounded-xl text-red-400 text-xs font-medium">
            ⚠️ {error}
          </div>
        )}

        {/* Formulario */}
        <form onSubmit={handleSubmit} className="space-y-4">
          
          {/* Campo: Nombre */}
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">
              Nombre Completo
            </label>
            <input
              type="text"
              name="fullName"
              required
              placeholder="Ej: Elías Vicencio"
              value={formData.fullName}
              onChange={handleChange}
              className="w-full bg-slate-950/60 border border-slate-900 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/10 transition-all"
            />
          </div>

          {/* Campo: Email */}
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">
              Correo Corporativo
            </label>
            <input
              type="email"
              name="email"
              required
              placeholder="operador@hyperion.ops"
              value={formData.email}
              onChange={handleChange}
              className="w-full bg-slate-950/60 border border-slate-900 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/10 transition-all"
            />
          </div>

          {/* Campo: Contraseña */}
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">
              Contraseña Temporal
            </label>
            <input
              type="password"
              name="password"
              required
              placeholder="••••••••••••"
              value={formData.password}
              onChange={handleChange}
              className="w-full bg-slate-950/60 border border-slate-900 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/10 transition-all"
            />
          </div>

          {/* Campo: Rol */}
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-1.5">
              Rol en el Sistema
            </label>
            <div className="relative">
              <select
                name="role"
                value={formData.role}
                onChange={handleChange}
                className="w-full bg-slate-950/60 border border-slate-900 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500/50 appearance-none cursor-pointer transition-all"
              >
                <option value="Operador perimetral" className="bg-[#050810]">Operador perimetral</option>
                <option value="Auditor de Sistemas" className="bg-[#050810]">Auditor de Sistemas</option>
                <option value="Administrador" className="bg-[#050810]">Administrador de Seguridad</option>
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-4 text-slate-500">
                <Shield size={14} />
              </div>
            </div>
          </div>

          {/* Acciones del Formulario */}
          <div className="flex gap-3 pt-3 border-t border-slate-900/60 mt-6">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="flex-1 bg-slate-900 hover:bg-slate-850 text-slate-400 hover:text-slate-200 font-medium rounded-xl py-2.5 text-xs sm:text-sm border border-slate-800/40 transition-all disabled:opacity-50"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl py-2.5 text-xs sm:text-sm transition-all shadow-lg shadow-blue-600/10 flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Registrando...
                </>
              ) : (
                'Registrar Operador'
              )}
            </button>
          </div>

        </form>
      </div>
    </div>
  );
}