import React, { useState, useEffect } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { X, Lock, ShieldCheck, Sun, Moon, KeyRound } from 'lucide-react';

export default function ConfiguracionFlotante({ isOpen, onClose }) {
  // --- Estados de la Interfaz ---
  const [activeTab, setActiveTab] = useState('seguridad'); 
  
  // 🌟 CAMBIO AQUÍ: Inicializar leyendo primero localStorage para evitar que se resetee al recargar la página
  const [isDarkMode, setIsDarkMode] = useState(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) return savedTheme === 'dark';
    return document.documentElement.classList.contains('dark');
  });

  // --- Estados de Formulario ---
  const [passwords, setPasswords] = useState({ current: '', new: '', confirm: '' });
  
  // --- Estados de Autenticación 2FA ---
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [qrUri, setQrUri] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [tokenInput, setTokenInput] = useState('');
  const [isActivated, setIsActivated] = useState(() => {
    return localStorage.getItem('two_factor_enabled') === 'true';
  });
  const [showDeactivateForm, setShowDeactivateForm] = useState(false);
  const [error2FA, setError2FA] = useState(null);
  const [loading2FA, setLoading2FA] = useState(false);

  const username = localStorage.getItem('user_email') || 'operador@hyperion.ops';

  // Sincronizar estado del 2FA desde la API
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

  // Manejo reactivo de temas
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

  const handleToggle2FA = async () => {
    setError2FA(null);
    setTokenInput('');

    if (isActivated) {
      setShowDeactivateForm(!showDeactivateForm);
      setTwoFactorEnabled(false);
    } else {
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
          throw new Error(data.detail || 'No se pudo configure el perímetro 2FA.');
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
    } catch (err) {
      setError2FA(err.message);
    } finally {
      setLoading2FA(false);
      setTokenInput('');
    }
  };

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
    setPasswords({ current: '', new: '', confirm: '' });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm transition-all">
      
      {/* Drawer Contenedor Principal */}
      <div className="w-full max-w-md h-full bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200 p-6 shadow-2xl flex flex-col border-l border-slate-200 dark:border-slate-900 transition-colors">
        
        {/* Cabecera */}
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-900 pb-4 mb-4">
          <div>
            <h2 className="text-lg font-bold text-blue-600 dark:text-blue-500 tracking-tight">Panel de Configuración</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Ajustes del perfil y perímetro del SGSI</p>
          </div>
          <button 
            onClick={onClose}
            className="text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-white p-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-850 border border-slate-200/60 dark:border-slate-800/80 transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Pestañas de Navegación */}
        <div className="flex border-b border-slate-200 dark:border-slate-900 mb-6 text-xs sm:text-sm">
          {['seguridad', '2fa', 'apariencia'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 pb-2.5 font-semibold capitalize transition-all border-b-2 text-center ${
                activeTab === tab 
                  ? 'text-blue-600 dark:text-blue-500 border-blue-600 dark:border-blue-500' 
                  : 'text-slate-500 dark:text-slate-400 border-transparent hover:text-slate-800 dark:hover:text-slate-200'
              }`}
            >
              {tab === 'seguridad' ? 'Contraseña' : tab === '2fa' ? 'Seguridad 2FA' : 'Apariencia'}
            </button>
          ))}
        </div>

        {/* Contenido Dinámico */}
        <div className="flex-1 overflow-y-auto pr-1">
          
          {/* PESTAÑA: CAMBIO DE CONTRASEÑA */}
          {activeTab === 'seguridad' && (
            <form onSubmit={handlePasswordChange} className="space-y-4">
              {['current', 'new', 'confirm'].map((field) => (
                <div key={field}>
                  <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400 mb-1.5">
                    {field === 'current' ? 'Contraseña Actual' : field === 'new' ? 'Nueva Contraseña' : 'Confirmar Nueva Contraseña'}
                  </label>
                  <input
                    type="password"
                    required
                    value={passwords[field]}
                    onChange={(e) => setPasswords({...passwords, [field]: e.target.value})}
                    className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-all"
                  />
                </div>
              ))}
              <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl py-2.5 text-sm transition-all shadow-lg shadow-blue-600/10 mt-2 flex items-center justify-center gap-2">
                <KeyRound size={16} /> Actualizar Credenciales
              </button>
            </form>
          )}

          {/* PESTAÑA: CONFIGURACIÓN 2FA */}
          {activeTab === '2fa' && (
            <div className="space-y-5">
              {error2FA && (
                <div className="bg-red-500/10 border border-red-500/20 p-3 rounded-xl text-red-400 text-xs">
                  {error2FA}
                </div>
              )}

              <div className="flex items-center justify-between bg-slate-50 dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800">
                <div className="pr-2">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">Autenticación de Dos Factores</h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    {isActivated ? '🔒 Cuenta protegida por perímetro dinámico.' : 'Añade tokens TOTP para blindar tus accesos.'}
                  </p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer shrink-0 select-none">
                  <input 
                    type="checkbox" 
                    checked={isActivated || twoFactorEnabled} 
                    disabled={loading2FA}
                    onChange={handleToggle2FA}
                    className="sr-only peer" 
                  />
                  <div className="w-11 h-6 bg-slate-200 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600 border border-slate-300 dark:border-slate-700"></div>
                </label>
              </div>

              {/* FLUJO QR */}
              {twoFactorEnabled && !isActivated && qrUri && (
                <div className="bg-slate-50/50 dark:bg-slate-900/40 border border-dashed border-slate-200 dark:border-slate-800 p-4 rounded-xl text-center space-y-4">
                  <p className="text-xs text-slate-600 dark:text-slate-400">Escanea el código con Google Authenticator o Bitwarden:</p>
                  <div className="bg-white p-3 inline-block rounded-xl mx-auto border border-slate-200 shadow-sm">
                    <QRCodeSVG value={qrUri} size={140} fgColor="#0f172a" />
                  </div>
                  <div className="text-[11px] bg-slate-100 dark:bg-slate-950 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 font-mono select-all text-blue-600 dark:text-blue-400 break-all">
                    Clave: {totpSecret}
                  </div>
                  <form onSubmit={handleVerifyAndActivate} className="space-y-3 pt-3 border-t border-slate-200 dark:border-slate-900 text-left">
                    <label className="block text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest">Código de Confirmación</label>
                    <div className="flex gap-2">
                      <input 
                        type="text" maxLength="6" placeholder="000000" value={tokenInput}
                        onChange={(e) => setTokenInput(e.target.value)}
                        className="flex-1 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl px-3 py-2 text-sm font-mono tracking-widest text-center text-slate-900 dark:text-white focus:outline-none focus:border-blue-500" required
                      />
                      <button type="submit" disabled={loading2FA} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-xl text-sm font-semibold transition-colors disabled:opacity-50">
                        {loading2FA ? '...' : 'Vincular'}
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {/* FLUJO DESACTIVACIÓN */}
              {showDeactivateForm && isActivated && (
                <div className="bg-red-500/[0.02] border border-dashed border-red-500/20 p-4 rounded-xl space-y-3">
                  <h5 className="text-xs font-bold text-red-500 uppercase tracking-wider flex items-center gap-1">⚠️ Confirmar Desactivación</h5>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Introduce el código actual para remover la protección.</p>
                  <form onSubmit={handleVerifyAndDeactivate} className="space-y-3 text-left">
                    <div className="flex gap-2">
                      <input 
                        type="text" maxLength="6" placeholder="000000" value={tokenInput}
                        onChange={(e) => setTokenInput(e.target.value)}
                        className="flex-1 bg-white dark:bg-slate-950 border border-red-500/20 rounded-xl px-3 py-2 text-sm font-mono tracking-widest text-center text-slate-900 dark:text-white focus:outline-none focus:border-red-500" required
                      />
                      <button type="submit" disabled={loading2FA} className="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded-xl text-sm font-semibold transition-colors disabled:opacity-50">
                        {loading2FA ? '...' : 'Remover'}
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {isActivated && !showDeactivateForm && (
                <div className="bg-emerald-500/5 dark:bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-xl text-center text-emerald-600 dark:text-emerald-400 text-xs font-semibold flex items-center justify-center gap-2">
                  <ShieldCheck size={16} /> Perímetro Asegurado por MFA activo
                </div>
              )}
            </div>
          )}

          {/* PESTAÑA: APARIENCIA */}
          {activeTab === 'apariencia' && (
            <div className="space-y-4">
              <label className="block text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400 mb-2">Tema de Interfaz</label>
              <div className="grid grid-cols-2 gap-4">
                <button
                  onClick={() => setIsDarkMode(false)}
                  className={`p-4 rounded-xl border flex flex-col items-center justify-center gap-2.5 transition-all ${
                    !isDarkMode 
                      ? 'bg-blue-50/60 dark:bg-blue-950/20 border-blue-500 text-blue-600 dark:text-blue-400 font-medium' 
                      : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  <Sun size={20} />
                  <span className="text-xs">Modo Claro</span>
                </button>
                <button
                  onClick={() => setIsDarkMode(true)}
                  className={`p-4 rounded-xl border flex flex-col items-center justify-center gap-2.5 transition-all ${
                    isDarkMode 
                      ? 'bg-blue-950/30 border-blue-500 text-blue-400 font-medium' 
                      : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  <Moon size={20} />
                  <span className="text-xs">Modo Oscuro</span>
                </button>
              </div>
            </div>
          )}

        </div>

        {/* Pie de Panel */}
        <div className="border-t border-slate-200 dark:border-slate-900 pt-4 mt-4 text-center">
          <p className="text-[10px] text-slate-400 dark:text-slate-500 tracking-widest uppercase font-mono">Hyperion Core Secure Engine v2.0</p>
        </div>
      </div>
    </div>
  );
}