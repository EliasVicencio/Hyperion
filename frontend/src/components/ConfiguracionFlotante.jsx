import React, { useState, useEffect } from 'react';
import { QRCodeSVG } from 'qrcode.react';

export default function ConfiguracionFlotante({ isOpen, onClose }) {
  // --- Estados de la Interfaz ---
  const [activeTab, setActiveTab] = useState('seguridad'); 
  const [isDarkMode, setIsDarkMode] = useState(() => {
    return document.documentElement.classList.contains('dark');
  });

  // --- Estados de Formulario ---
  const [passwords, setPasswords] = useState({ current: '', new: '', confirm: '' });
  
  // --- Estados Sincronizados con el Backend para 2FA Real ---
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [qrUri, setQrUri] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [tokenInput, setTokenInput] = useState('');
  const [isActivated, setIsActivated] = useState(() => {
    return localStorage.getItem('two_factor_enabled') === 'true';
  });
  const [showDeactivateForm, setShowDeactivateForm] = useState(false); // Controla la UI de desactivación
  const [error2FA, setError2FA] = useState(null);
  const [loading2FA, setLoading2FA] = useState(false);

  // Intentamos recuperar el email guardado en el login
  const username = localStorage.getItem('user_email') || 'operador@hyperion.ops';

  // --- NUEVO: Sincronizar estado real del 2FA desde la base de datos al abrir el Panel ---
  useEffect(() => {
    if (isOpen && username) {
      fetch(`/auth/status-2fa?username=${encodeURIComponent(username)}`)
        .then((res) => res.json())
        .then((data) => {
          setIsActivated(data.two_factor_enabled);
          localStorage.setItem('two_factor_enabled', data.two_factor_enabled ? 'true' : 'false');
        })
        .catch((err) => console.error("Error sincronizando estado perimetral 2FA:", err));
    }
  }, [isOpen, username]);

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

  // Lógica del Switch: Maneja la activación o el despliegue del formulario de desactivación segura
  const handleToggle2FA = async () => {
    setError2FA(null);
    setTokenInput('');

    if (isActivated) {
      // Si ya está activo, desplegamos/ocultamos el subformulario para pedir el token y apagarlo
      setShowDeactivateForm(!showDeactivateForm);
      setTwoFactorEnabled(false);
    } else {
      // Si está apagado, manejamos la inicialización del flujo normal QR
      if (twoFactorEnabled) {
        setTwoFactorEnabled(false);
        return;
      }

      setLoading2FA(true);
      try {
        const response = await fetch(`/auth/setup-2fa?username=${encodeURIComponent(username)}`, {
          method: 'POST',
        });
        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.detail || 'No se pudo configurar el perímetro 2FA.');
        }

        setTotpSecret(data.secret);
        setQrUri(data.qr_uri);
        setTwoFactorEnabled(true);
      } catch (err) {
        setError2FA(err.message);
      } finally {
        setLoading2FA(false);
      }
    }
  };

  // Confirmación final para ACTIVAR enviando el token de 6 dígitos
  const handleVerifyAndActivate = async (e) => {
    e.preventDefault();
    setError2FA(null);
    setLoading2FA(true);

    try {
      const response = await fetch('/auth/activate-2fa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, token: tokenInput }),
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Código incorrecto. Inténtalo de nuevo.');
      }

      setIsActivated(true);
      setTwoFactorEnabled(false); 
      localStorage.setItem('two_factor_enabled', 'true');
      alert('¡Autenticación de dos factores vinculada exitosamente!');
    } catch (err) {
      setError2FA(err.message);
    } finally {
      setLoading2FA(false);
      setTokenInput('');
    }
  };

  // NUEVO: Confirmación final para DESACTIVAR enviando el token de 6 dígitos
  const handleVerifyAndDeactivate = async (e) => {
    e.preventDefault();
    setError2FA(null);
    setLoading2FA(true);

    try {
      const response = await fetch('/auth/deactivate-2fa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, token: tokenInput }),
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Código de seguridad incorrecto.');
      }

      setIsActivated(false);
      setShowDeactivateForm(false);
      localStorage.setItem('two_factor_enabled', 'false');
      alert('La autenticación de dos factores ha sido removida del perímetro.');
    } catch (err) {
      setError2FA(err.message);
    } finally {
      setLoading2FA(false);
      setTokenInput('');
    }
  };

  const handlePasswordChange = (e) => {
    e.preventDefault();
    if (passwords.new !== passwords.confirm) {
      alert('Las contraseñas nuevas no coinciden');
      return;
    }
    alert('Solicitud de cambio de clave enviada al perímetro.');
    setPasswords({ current: '', new: '', confirm: '' });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/50 backdrop-blur-sm animate-fade-in">
      
      {/* Contenedor Adaptable (Dark / Light Mode Nativo) */}
      <div className="w-full max-w-md h-full dark:bg-slate-900 bg-white dark:text-slate-100 text-slate-800 p-6 shadow-2xl flex flex-col dark:border-slate-800 border-slate-200 border-l animate-slide-in">
        
        {/* Cabecera */}
        <div className="flex items-center justify-between border-b dark:border-slate-800 border-slate-200 pb-4 mb-4">
          <div>
            <h2 className="text-xl font-bold dark:text-blue-400 text-blue-600">Panel de Configuración</h2>
            <p className="text-xs dark:text-slate-400 text-slate-500">Ajustes del perfil y perímetro del SGSI</p>
          </div>
          <button 
            onClick={onClose}
            className="dark:text-slate-400 text-slate-500 dark:hover:text-white hover:text-black p-2 rounded-lg dark:bg-slate-800 bg-slate-100 dark:hover:bg-slate-700 hover:bg-slate-200 transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Navegación por Pestañas */}
        <div className="flex border-b dark:border-slate-800 border-slate-200 mb-6 text-sm">
          {['seguridad', '2fa', 'apariencia'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 pb-2 font-medium capitalize transition-colors ${
                activeTab === tab 
                  ? 'dark:text-blue-400 text-blue-600 border-b-2 dark:border-blue-400 border-blue-600' 
                  : 'dark:text-slate-400 text-slate-500 dark:hover:text-slate-200 hover:text-slate-800'
              }`}
            >
              {tab === 'seguridad' ? 'Contraseña' : tab === '2fa' ? 'Seguridad 2FA' : 'Apariencia'}
            </button>
          ))}
        </div>

        {/* Contenido Dinámico */}
        <div className="flex-1 overflow-y-auto pr-1">
          
          {/* PESTAÑA: CAMBIO DE CLAVES */}
          {activeTab === 'seguridad' && (
            <form onSubmit={handlePasswordChange} className="space-y-4">
              {['current', 'new', 'confirm'].map((field) => (
                <div key={field}>
                  <label className="block text-xs font-semibold uppercase tracking-wider dark:text-slate-400 text-slate-500 mb-1">
                    {field === 'current' ? 'Contraseña Actual' : field === 'new' ? 'Nueva Contraseña' : 'Confirmar Nueva Contraseña'}
                  </label>
                  <input
                    type="password"
                    required
                    value={passwords[field]}
                    onChange={(e) => setPasswords({...passwords, [field]: e.target.value})}
                    className="w-full dark:bg-slate-800 bg-slate-50 border dark:border-slate-700 border-slate-300 rounded-lg px-3 py-2 text-sm focus:outline-none dark:focus:border-blue-500 focus:border-blue-600 dark:text-white text-slate-900"
                  />
                </div>
              ))}
              <button type="submit" className="w-full dark:bg-blue-600 bg-blue-600 hover:dark:bg-blue-500 hover:bg-blue-700 text-white font-medium rounded-lg py-2 text-sm transition-colors mt-2">
                Actualizar Credenciales de Acceso
              </button>
            </form>
          )}

          {/* PESTAÑA: CONFIGURACIÓN 2FA */}
          {activeTab === '2fa' && (
            <div className="space-y-6">
              {error2FA && (
                <div className="bg-red-500/10 border border-red-500/20 p-3 rounded-xl text-red-400 text-xs">
                  {error2FA}
                </div>
              )}

              <div className="flex items-center justify-between dark:bg-slate-800 bg-slate-50 p-4 rounded-xl border dark:border-slate-700 border-slate-200">
                <div>
                  <h4 className="text-sm font-bold dark:text-white text-slate-900">Autenticación de Dos Factores</h4>
                  <p className="text-xs dark:text-slate-400 text-slate-500 mt-0.5">
                    {isActivated ? '🔒 Tu cuenta está protegida.' : 'Añade un token TOTP dinámico para proteger la cuenta.'}
                  </p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input 
                    type="checkbox" 
                    checked={isActivated || twoFactorEnabled} 
                    disabled={loading2FA}
                    onChange={handleToggle2FA}
                    className="sr-only peer" 
                  />
                  <div className="w-11 h-6 bg-slate-300 dark:bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>

              {/* FLUJO DE NUEVA ACTIVACIÓN: Código QR */}
              {twoFactorEnabled && !isActivated && qrUri && (
                <div className="dark:bg-slate-800/50 bg-slate-50/50 border border-dashed dark:border-slate-700 border-slate-300 p-4 rounded-xl text-center space-y-4 animate-fade-in">
                  <p className="text-xs dark:text-slate-300 text-slate-600">Escanea este código o introduce la clave en tu app autenticadora:</p>
                  <div className="bg-white p-3 inline-block rounded-xl mx-auto shadow-xl border border-slate-200">
                    <QRCodeSVG value={qrUri} size={150} fgColor="#020617" />
                  </div>
                  <div className="text-xs dark:bg-slate-950 bg-slate-100 p-2 rounded dark:border-slate-800 border-slate-300 font-mono select-all dark:text-blue-400 text-blue-600">
                    Secreto: {totpSecret}
                  </div>
                  <form onSubmit={handleVerifyAndActivate} className="space-y-3 pt-3 border-t dark:border-slate-800 border-slate-200 text-left">
                    <label className="block text-xs font-semibold dark:text-slate-400 text-slate-500 uppercase tracking-wider">Código de Activación</label>
                    <div className="flex gap-2">
                      <input 
                        type="text" maxLength="6" placeholder="000000" value={tokenInput}
                        onChange={(e) => setTokenInput(e.target.value)}
                        className="flex-1 dark:bg-slate-950 bg-white border dark:border-slate-800 border-slate-300 rounded-lg px-3 py-2 text-sm font-mono tracking-widest text-center dark:text-white text-slate-900 focus:outline-none focus:border-blue-500" required
                      />
                      <button type="submit" disabled={loading2FA} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                        {loading2FA ? '...' : 'Vincular'}
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {/* FLUJO DE DESACTIVACIÓN SEGURA: Pide Token */}
              {showDeactivateForm && isActivated && (
                <div className="dark:bg-red-950/10 bg-red-50/10 border border-dashed border-red-500/30 p-4 rounded-xl space-y-3 animate-fade-in">
                  <h5 className="text-xs font-bold text-red-500 uppercase tracking-wider">⚠️ Confirmar Desactivación</h5>
                  <p className="text-xs dark:text-slate-400 text-slate-600">Para remover el segundo factor, ingresa el código de 6 dígitos actual de tu aplicación.</p>
                  <form onSubmit={handleVerifyAndDeactivate} className="space-y-3 pt-1 text-left">
                    <div className="flex gap-2">
                      <input 
                        type="text" maxLength="6" placeholder="000000" value={tokenInput}
                        onChange={(e) => setTokenInput(e.target.value)}
                        className="flex-1 dark:bg-slate-950 bg-white border border-red-500/30 rounded-lg px-3 py-2 text-sm font-mono tracking-widest text-center dark:text-white text-slate-900 focus:outline-none focus:border-red-500" required
                      />
                      <button type="submit" disabled={loading2FA} className="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                        {loading2FA ? '...' : 'Remover'}
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {isActivated && !showDeactivateForm && (
                <div className="dark:bg-emerald-500/10 bg-emerald-50/10 border dark:border-emerald-500/20 border-emerald-500/30 p-4 rounded-xl text-center text-emerald-600 dark:text-emerald-400 text-xs font-medium">
                  🔒 Perímetro Asegurado: El segundo factor de autenticación está activo.
                </div>
              )}
            </div>
          )}

          {/* PESTAÑA: APARIENCIA Y TEMAS */}
          {activeTab === 'apariencia' && (
            <div className="space-y-4">
              <label className="block text-xs font-semibold uppercase tracking-wider dark:text-slate-400 text-slate-500 mb-2">Tema de la Aplicación</label>
              <div className="grid grid-cols-2 gap-4">
                <button
                  onClick={() => setIsDarkMode(false)}
                  className={`p-4 rounded-xl border flex flex-col items-center justify-center gap-2 transition-all ${!isDarkMode ? 'bg-blue-50 dark:bg-blue-950/40 border-blue-500 text-blue-600 dark:text-blue-400' : 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:border-slate-300'}`}
                >
                  <span className="text-2xl">☀️</span> <span className="text-xs font-semibold">Modo Claro</span>
                </button>
                <button
                  onClick={() => setIsDarkMode(true)}
                  className={`p-4 rounded-xl border flex flex-col items-center justify-center gap-2 transition-all ${isDarkMode ? 'bg-blue-950/40 border-blue-500 text-blue-400' : 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:border-slate-600'}`}
                >
                  <span className="text-2xl">🌙</span> <span className="text-xs font-semibold">Modo Oscuro</span>
                </button>
              </div>
            </div>
          )}

        </div>

        {/* Pie de Panel */}
        <div className="border-t dark:border-slate-800 border-slate-200 pt-4 mt-4 text-center">
          <p className="text-[10px] text-slate-400 dark:text-slate-500 tracking-widest uppercase font-mono">Hyperion Core Secure Engine v2.0</p>
        </div>
      </div>
    </div>
  );
}