import React, { useState, useEffect } from 'react';
import { Shield, Mail, Lock, User, ArrowRight, Eye, EyeOff, AlertCircle, Loader2 } from 'lucide-react';
import { setToken } from '../api';

export default function Login({ onLoginSuccess }) {
  const [view, setView] = useState('login'); // 'login', 'register', 'recovery', '2fa'
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [nombre, setNombre] = useState('');
  const [token2FA, setToken2FA] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  const ejecutarAccion = async () => {
    setError(null);
    setSuccessMessage(null);
    setLoading(true);

    try {
      // 1. FLUJO: VERIFICACIÓN 2FA ESTÁNDAR
      if (view === '2fa') {
        const response = await fetch('/auth/verify-2fa', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: email, token: token2FA }),
        });
        const data = await response.json();

        if (!response.ok) {
          setToken2FA(''); // limpio el campo para que un reintento dispare el auto-envío de nuevo
          throw new Error(data.detail || 'Código de seguridad incorrecto.');
        }

        setToken(data.access_token);
        localStorage.setItem('user_email', email);
        localStorage.setItem('two_factor_enabled', 'true');
        onLoginSuccess();
        return;
      }

      // 2. FLUJO: RECOVERY (¿Olvidaste tu clave?)
      if (view === 'recovery') {
        const response = await fetch('/auth/recover-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: email, new_password: password, token: token2FA }),
        });
        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.detail || 'Fallo en la verificación perimetral.');
        }

        setSuccessMessage('¡Contraseña actualizada con éxito! Ya puedes autenticarte.');
        setTimeout(() => {
          setView('login');
          setPassword('');
          setToken2FA('');
          setSuccessMessage(null);
        }, 2500);
        return;
      }

      // 3. FLUJO: REGISTRO DE OPERADOR
      if (view === 'register') {
        const response = await fetch('/api/v1/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password, nombre, role: 'operador' }),
        });

        if (!response.headers.get('content-type')?.includes('application/json')) {
          throw new Error('El backend no respondió JSON. Revisa el proxy en vercel.json del frontend.');
        }

        const data = await response.json();

        if (!response.ok) {
          const detail = Array.isArray(data.detail)
            ? data.detail.map((d) => d.msg).join(' / ')
            : data.detail;
          throw new Error(detail || 'No se pudo registrar el operador.');
        }

        setView('login');
        setPassword('');
        setNombre('');
      } 
      // 4. FLUJO: LOGIN TRADICIONAL
      else {
        const body = new URLSearchParams();
        body.set('username', email);
        body.set('password', password);

        const response = await fetch('/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });

        if (!response.headers.get('content-type')?.includes('application/json')) {
          throw new Error('El backend no respondió JSON. Revisa el proxy en vercel.json del frontend.');
        }

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.detail || 'Credenciales incorrectas.');
        }

        if (data.status === 'requires_2fa') {
          setView('2fa');
        } else {
          setToken(data.access_token);
          localStorage.setItem('user_email', data.username);
          localStorage.setItem('two_factor_enabled', 'false');
          onLoginSuccess();
        }
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    ejecutarAccion();
  };

  // Auto-envío: apenas se completan los 6 dígitos del token 2FA en el login,
  // se valida solo, sin esperar a que el usuario toque "Verificar Token".
  useEffect(() => {
    if (view === '2fa' && token2FA.length === 6 && !loading) {
      ejecutarAccion();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token2FA, view]);

  return (
    <div className="min-h-screen bg-hyperion-lightBg dark:bg-hyperion-dark flex items-center justify-center p-4 relative overflow-hidden font-sans selection:bg-blue-500/30 transition-colors duration-300">
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-blue-600/10 blur-[120px] rounded-full pointer-events-none"></div>
      <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 translate-y-1/2 w-[400px] h-[400px] bg-purple-600/5 blur-[100px] rounded-full pointer-events-none"></div>

      <div className="w-full max-w-md bg-white/80 dark:bg-[#0b111e]/80 border border-hyperion-lightBorder dark:border-slate-800/80 backdrop-blur-xl rounded-3xl p-8 shadow-xl dark:shadow-2xl relative z-10 transition-colors">

        {/* Encabezado e Isotipo */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center shadow-xl shadow-blue-500/10 mb-4">
            <Shield className="text-white" size={24} />
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white transition-colors">
            {view === '2fa' && 'Verificación de Seguridad'}
            {view === 'register' && 'Crear cuenta Hyperion'}
            {view === 'recovery' && 'Recuperar Credenciales'}
            {view === 'login' && 'Acceso al Sistema'}
          </h2>
          <p className="text-slate-500 dark:text-slate-400 text-xs mt-1.5 max-w-[280px] transition-colors">
            {view === '2fa' && 'Introduce el código de 6 dígitos de tu aplicación de autenticación para validar la firma perimetral.'}
            {view === 'register' && 'Regístrate para la gestión unificada de políticas e incidentes SGSI.'}
            {view === 'recovery' && 'Ingresa tu correo, la nueva clave y tu token OTP para forzar el restablecimiento.'}
            {view === 'login' && 'Introduce tus credenciales autorizadas para iniciar auditoría.'}
          </p>
        </div>

        {/* Formulario */}
        <form onSubmit={handleSubmit} className="space-y-4">

          {error && (
            <div className="bg-red-500/10 border border-red-500/20 p-3 rounded-xl text-red-600 dark:text-red-400 flex items-start gap-2.5 text-xs transition-colors">
              <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {successMessage && (
            <div className="bg-emerald-500/10 border border-emerald-500/20 p-3 rounded-xl text-emerald-600 dark:text-emerald-400 flex items-start gap-2.5 text-xs transition-colors">
              <Shield size={16} className="flex-shrink-0 mt-0.5" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* VISTA FORMULARIO (LOGIN / REGISTER / RECOVERY) */}
          {view !== '2fa' && (
            <>
              {view === 'register' && (
                <div className="space-y-1.5">
                  <label className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider block transition-colors">Nombre Completo</label>
                  <div className="relative">
                    <User className="absolute left-3.5 top-3 text-slate-400 dark:text-slate-500" size={16} />
                    <input
                      type="text"
                      required
                      placeholder="Elias Vicencio"
                      className="w-full bg-slate-50 dark:bg-slate-950/60 border border-hyperion-lightBorder dark:border-slate-800 rounded-xl py-2.5 pl-11 pr-4 text-sm text-slate-900 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-600 focus:border-blue-500 outline-none transition-all"
                      value={nombre}
                      onChange={(e) => setNombre(e.target.value)}
                    />
                  </div>
                </div>
              )}

              <div className="space-y-1.5">
                <label className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider block transition-colors">Correo Corporativo</label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-3 text-slate-400 dark:text-slate-500" size={16} />
                  <input
                    type="email"
                    required
                    placeholder="admin@hyperion.ops"
                    className="w-full bg-slate-50 dark:bg-slate-950/60 border border-hyperion-lightBorder dark:border-slate-800 rounded-xl py-2.5 pl-11 pr-4 text-sm text-slate-900 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-600 focus:border-blue-500 outline-none transition-all"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex justify-between items-center">
                  <label className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider block transition-colors">
                    {view === 'recovery' ? 'Nueva Contraseña' : 'Contraseña'}
                  </label>
                  {view === 'login' && (
                    <button 
                      type="button" 
                      onClick={() => { setView('recovery'); setError(null); setPassword(''); }}
                      className="text-[11px] text-blue-600 dark:text-blue-500 hover:underline transition-colors focus:outline-none"
                    >
                      ¿Olvidaste tu clave?
                    </button>
                  )}
                </div>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-3 text-slate-400 dark:text-slate-500" size={16} />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    placeholder="••••••••••••"
                    className="w-full bg-slate-50 dark:bg-slate-950/60 border border-hyperion-lightBorder dark:border-slate-800 rounded-xl py-2.5 pl-11 pr-10 text-sm text-slate-900 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-600 focus:border-blue-500 outline-none transition-all"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-3 text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              {/* EN CASO DE RECUPERACIÓN, SE EXIGE EL CAPTURE DEL TOKEN EN ESTE MISMO BLOQUE */}
              {view === 'recovery' && (
                <div className="space-y-1.5">
                  <label className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider block transition-colors">Código de Seguridad 2FA (TOTP)</label>
                  <input
                    type="text"
                    maxLength="6"
                    placeholder="000000"
                    required
                    value={token2FA}
                    onChange={(e) => setToken2FA(e.target.value.replace(/\D/g, ''))}
                    className="w-full bg-slate-50 dark:bg-slate-950/60 border border-hyperion-lightBorder dark:border-slate-800 rounded-xl py-2.5 text-center text-md font-mono tracking-[0.3em] text-blue-600 dark:text-blue-400 focus:border-blue-500 outline-none transition-all"
                  />
                </div>
              )}
            </>
          )}

          {/* VISTA EXCLUSIVA: SÓLO INPUT DE TOKEN EN LOGINS CON 2FA REQUERIDO */}
          {view === '2fa' && (
            <div className="space-y-2 animate-fade-in text-center">
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength="6"
                placeholder="000000"
                required
                autoFocus
                value={token2FA}
                onChange={(e) => setToken2FA(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-hyperion-lightBorder dark:border-slate-800 rounded-2xl py-3 text-center text-xl font-mono tracking-[0.5em] text-blue-600 dark:text-blue-400 focus:border-blue-500 outline-none transition-all"
              />
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-xl text-sm mt-2 flex items-center justify-center gap-2 transition-all shadow-lg shadow-blue-600/10 group"
          >
            {loading ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <>
                {view === '2fa' && 'Verificar Token'}
                {view === 'register' && 'Registrar Operador'}
                {view === 'recovery' && 'Restablecer Acceso'}
                {view === 'login' && 'Autenticar'}
                <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
              </>
            )}
          </button>
        </form>

        {/* FOOTER INTERACTIVO PARA VOLVER O CAMBIAR DE VISTAS */}
        <div className="mt-6 pt-4 border-t border-hyperion-lightBorder dark:border-slate-900 text-center transition-colors">
          <p className="text-xs text-slate-500 dark:text-slate-400 transition-colors">
            {view === 'recovery' && (
              <button
                type="button"
                onClick={() => { setView('login'); setError(null); }}
                className="text-blue-600 dark:text-blue-500 font-medium hover:underline transition-colors"
              >
                Volver al inicio de sesión
              </button>
            )}
            {view === 'register' && (
              <>
                ¿Ya tienes una credencial?
                <button
                  type="button"
                  onClick={() => { setView('login'); setNombre(''); setError(null); }}
                  className="text-blue-600 dark:text-blue-500 font-medium hover:underline pl-1 transition-colors"
                >
                  Inicia Sesión
                </button>
              </>
            )}
            {view === 'login' && (
              <>
                ¿Nuevo operador en el perímetro?
                <button
                  type="button"
                  onClick={() => { setView('register'); setNombre(''); setError(null); }}
                  className="text-blue-600 dark:text-blue-500 font-medium hover:underline pl-1 transition-colors"
                >
                  Crea una cuenta
                </button>
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  );
}