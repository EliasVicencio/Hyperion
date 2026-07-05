import React, { useState, useEffect } from 'react';

export default function ConfiguracionFlotante({ isOpen, onClose }) {
  // --- Estados de la Interfaz ---
  const [activeTab, setActiveTab] = useState('seguridad'); // 'seguridad', '2fa', 'apariencia'
  const [isDarkMode, setIsDarkMode] = useState(() => {
    return document.documentElement.classList.contains('dark');
  });

  // --- Estados de Formulario ---
  const [passwords, setPasswords] = useState({ current: '', new: '', confirm: '' });
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [totpSecret, setTotpSecret] = useState('JBSWY3DPEHPK3PXP'); // Sincronizado con tu .env

  // --- Efecto para el Cambio de Tema ---
  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  }, [isDarkMode]);

  if (!isOpen) return null;

  const handlePasswordChange = (e) => {
    e.preventDefault();
    if (passwords.new !== passwords.confirm) {
      alert('Las contraseñas nuevas no coinciden');
      return;
    }
    // Aquí invocas a tu proxy: fetch('/api/v1/auth/change-password', ...)
    alert('Solicitud de cambio de clave enviada al perímetro.');
    setPasswords({ current: '', new: '', confirm: '' });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end bg-black bg-opacity-50 backdrop-blur-sm animate-fade-in">
      {/* Contenedor Flotante (Drawer Derecho) */}
      <div className="w-full max-w-md h-full bg-slate-900 text-slate-100 p-6 shadow-2xl flex flex-col border-l border-slate-800 animate-slide-in">
        
        {/* Cabecera */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
          <div>
            <h2 className="text-xl font-bold text-blue-400">Panel de Configuración</h2>
            <p className="text-xs text-slate-400">Ajustes del perfil y perímetro del SGSI</p>
          </div>
          <button 
            onClick={onClose}
            className="text-slate-400 hover:text-white p-2 rounded-lg bg-slate-800 hover:bg-slate-700 transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Navegación por Pestañas */}
        <div className="flex border-b border-slate-800 mb-6 text-sm">
          <button
            onClick={() => setActiveTab('seguridad')}
            className={`flex-1 pb-2 font-medium transition-colors ${activeTab === 'seguridad' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Contraseña
          </button>
          <button
            onClick={() => setActiveTab('2fa')}
            className={`flex-1 pb-2 font-medium transition-colors ${activeTab === '2fa' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Seguridad 2FA
          </button>
          <button
            onClick={() => setActiveTab('apariencia')}
            className={`flex-1 pb-2 font-medium transition-colors ${activeTab === 'apariencia' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-slate-400 hover:text-slate-200'}`}
          >
            Apariencia
          </button>
        </div>

        {/* Contenido Dinámico */}
        <div className="flex-1 overflow-y-auto pr-1">
          
          {/* PESTAÑA: CAMBIO DE CLAVES */}
          {activeTab === 'seguridad' && (
            <form onSubmit={handlePasswordChange} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Contraseña Actual</label>
                <input
                  type="password"
                  required
                  value={passwords.current}
                  onChange={(e) => setPasswords({...passwords, current: e.target.value})}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 text-white"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Nueva Contraseña</label>
                <input
                  type="password"
                  required
                  value={passwords.new}
                  onChange={(e) => setPasswords({...passwords, new: e.target.value})}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 text-white"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Confirmar Nueva Contraseña</label>
                <input
                  type="password"
                  required
                  value={passwords.confirm}
                  onChange={(e) => setPasswords({...passwords, confirm: e.target.value})}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 text-white"
                />
              </div>
              <button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg py-2 text-sm transition-colors mt-2"
              >
                Actualizar Credenciales de Acceso
              </button>
            </form>
          )}

          {/* PESTAÑA: CONFIGURACIÓN 2FA */}
          {activeTab === '2fa' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between bg-slate-800 p-4 rounded-xl border border-slate-700">
                <div>
                  <h4 className="text-sm font-bold text-white">Autenticación de Dos Factores</h4>
                  <p className="text-xs text-slate-400 mt-0.5">Añade un token TOTP dinámico para proteger la cuenta.</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={twoFactorEnabled} 
                    onChange={() => setTwoFactorEnabled(!twoFactorEnabled)}
                    className="sr-only peer" 
                  />
                  <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>

              {twoFactorEnabled && (
                <div className="bg-slate-800/50 border border-dashed border-slate-700 p-4 rounded-xl text-center space-y-4 animate-fade-in">
                  <p className="text-xs text-slate-300">Escanea este código o introduce la clave en tu app autenticadora (Google Auth / Authy)</p>
                  
                  {/* Marcador de posición para el QR generado con el TOTP_SECRET de tu .env */}
                  <div className="w-40 h-40 bg-white mx-auto flex items-center justify-center rounded-lg shadow-inner">
                    <span className="text-xs text-slate-800 font-mono font-bold">[ CÓDIGO QR TOTP ]</span>
                  </div>
                  
                  <div className="text-xs bg-slate-900 p-2 rounded border border-slate-800 font-mono select-all text-blue-400">
                    Secreto: {totpSecret}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* PESTAÑA: APARIENCIA Y TEMAS */}
          {activeTab === 'apariencia' && (
            <div className="space-y-4">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Tema de la Aplicación</label>
              <div className="grid grid-cols-2 gap-4">
                <button
                  onClick={() => setIsDarkMode(false)}
                  className={`p-4 rounded-xl border flex flex-col items-center justify-center gap-2 transition-all ${!isDarkMode ? 'bg-blue-950/40 border-blue-500 text-blue-400' : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'}`}
                >
                  <span className="text-2xl">☀️</span>
                  <span className="text-xs font-semibold">Modo Claro</span>
                </button>
                <button
                  onClick={() => setIsDarkMode(true)}
                  className={`p-4 rounded-xl border flex flex-col items-center justify-center gap-2 transition-all ${isDarkMode ? 'bg-blue-950/40 border-blue-500 text-blue-400' : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'}`}
                >
                  <span className="text-2xl">🌙</span>
                  <span className="text-xs font-semibold">Modo Oscuro</span>
                </button>
              </div>
            </div>
          )}

        </div>

        {/* Pie de Panel */}
        <div className="border-t border-slate-800 pt-4 mt-4 text-center">
          <p className="text-[10px] text-slate-500 tracking-widest uppercase font-mono">Hyperion Core Secure Engine v2.0</p>
        </div>
      </div>
    </div>
  );
}