import React, { useState } from 'react';
import { Shield, Mail, Lock, User, ArrowRight, Eye, EyeOff } from 'lucide-react';

export default function Login({ onLoginSuccess }) {
  const [isRegister, setIsRegister] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [nombre, setNombre] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    // Aquí conectarás con tu FastAPI /api/v1/auth/token en el futuro.
    // Por ahora, simulamos el éxito:
    onLoginSuccess();
  };

  return (
    <div className="min-h-screen bg-[#020617] flex items-center justify-center p-4 relative overflow-hidden font-sans selection:bg-blue-500/30">
      {/* Efecto de luz de fondo cyberpunk */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-blue-600/10 blur-[120px] rounded-full pointer-events-none"></div>
      <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 translate-y-1/2 w-[400px] h-[400px] bg-purple-600/5 blur-[100px] rounded-full pointer-events-none"></div>

      {/* Tarjeta Contenedora Principal */}
      <div className="w-full max-w-md bg-[#0b111e]/80 border border-slate-800/80 backdrop-blur-xl rounded-3xl p-8 shadow-2xl relative z-10">
        
        {/* Encabezado e Isotipo */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center shadow-xl shadow-blue-500/10 mb-4">
            <Shield className="text-white" size={24} />
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-white">
            {isRegister ? 'Crear cuenta Hyperion' : 'Acceso al Sistema'}
          </h2>
          <p className="text-slate-500 text-xs mt-1.5 max-w-[280px]">
            {isRegister 
              ? 'Regístrate para la gestión unificada de políticas e incidentes SGSI.' 
              : 'Introduce tus credenciales autorizadas para iniciar auditoría.'}
          </p>
        </div>

        {/* Formulario */}
        <form onSubmit={handleSubmit} className="space-y-4">
          
          {/* Campo Nombre (Solo si es Registro) */}
          {isRegister && (
            <div className="space-y-1.5">
              <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">Nombre Completo</label>
              <div className="relative">
                <User className="absolute left-3.5 top-3 text-slate-500" size={16} />
                <input
                  type="text"
                  required
                  placeholder="Elias Vicencio"
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-xl py-2.5 pl-11 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:border-blue-500 outline-none transition-all"
                  value={nombre}
                  onChange={(e) => setNombre(e.target.value)}
                />
              </div>
            </div>
          )}

          {/* Campo Email */}
          <div className="space-y-1.5">
            <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">Correo Corporativo</label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-3 text-slate-500" size={16} />
              <input
                type="email"
                required
                placeholder="admin@hyperion.ops"
                className="w-full bg-slate-950/60 border border-slate-800 rounded-xl py-2.5 pl-11 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:border-blue-500 outline-none transition-all"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>

          {/* Campo Contraseña */}
          <div className="space-y-1.5">
            <div className="flex justify-between items-center">
              <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">Contraseña</label>
              {!isRegister && (
                <a href="#forgot" className="text-[11px] text-blue-500 hover:underline">¿Olvidaste tu clave?</a>
              )}
            </div>
            <div className="relative">
              <Lock className="absolute left-3.5 top-3 text-slate-500" size={16} />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="••••••••••••"
                className="w-full bg-slate-950/60 border border-slate-800 rounded-xl py-2.5 pl-11 pr-10 text-sm text-slate-200 placeholder-slate-600 focus:border-blue-500 outline-none transition-all"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-3 text-slate-500 hover:text-slate-300 transition-colors"
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {/* Botón de Envío */}
          <button
            type="submit"
            className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5 rounded-xl text-sm mt-2 flex items-center justify-center gap-2 transition-all shadow-lg shadow-blue-600/10 group"
          >
            {isRegister ? 'Registrar Operador' : 'Autenticar'} 
            <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
          </button>
        </form>

        {/* Selector de modo (Login / Registro) */}
        <div className="mt-6 pt-4 border-t border-slate-900 text-center">
          <p className="text-xs text-slate-500">
            {isRegister ? '¿Ya tienes una credencial?' : '¿Nuevo operador en el perímetro?'}
            <button
              onClick={() => {
                setIsRegister(!isRegister);
                setNombre('');
              }}
              className="text-blue-500 font-medium hover:underline pl-1"
            >
              {isRegister ? 'Inicia Sesión' : 'Crea una cuenta'}
            </button>
          </p>
        </div>

      </div>
    </div>
  );
}