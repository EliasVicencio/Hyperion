import React, { useState } from 'react';

export default function RecuperarContrasenaModal({ isOpen, onClose }) {
  const [email, setEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [token2FA, setToken2FA] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });

  if (!isOpen) return null;

  const handleRecovery = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ type: '', text: '' });

    try {
      const response = await fetch('/auth/recover-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: email,
          new_password: newPassword,
          token: token2FA
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Fallo en la verificación perimetral.');
      }

      setMessage({ type: 'success', text: '¡Contraseña actualizada! Ya puedes iniciar sesión con tus nuevas credenciales.' });
      setTimeout(() => {
        onClose();
        setEmail('');
        setNewPassword('');
        setToken2FA('');
        setMessage({ type: '', text: '' });
      }, 3000);

    } catch (error) {
      setMessage({ type: 'error', text: error.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-70 backdrop-blur-sm">
      <div className="w-full max-w-md p-6 bg-[#0d1117] border border-gray-800 rounded-xl shadow-2xl">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            🛡️ Recuperación Autogestionada
          </h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors">✕</button>
        </div>
        
        <p className="text-sm text-gray-400 mb-4">
          Introduce tus datos corporativos junto al código OTP de tu aplicación autenticadora para forzar el cambio de credencial.
        </p>

        <form onSubmit={handleRecovery} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Correo Corporativo</label>
            <input 
              type="email" 
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 bg-[#161b22] border border-gray-700 text-white rounded-lg focus:outline-none focus:border-blue-500"
              placeholder="admin@hyperion.ops"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Nueva Contraseña</label>
            <input 
              type="password" 
              required
              minLength={8}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-3 py-2 bg-[#161b22] border border-gray-700 text-white rounded-lg focus:outline-none focus:border-blue-500"
              placeholder="••••••••••••"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Código de Seguridad de 2FA (TOTP)</label>
            <input 
              type="text" 
              required
              maxLength={6}
              value={token2FA}
              onChange={(e) => setToken2FA(e.target.value.replace(/\D/g, ''))}
              className="w-full px-3 py-2 text-center text-lg font-mono tracking-widest bg-[#161b22] border border-gray-700 text-blue-400 rounded-lg focus:outline-none focus:border-blue-500"
              placeholder="000000"
            />
          </div>

          {message.text && (
            <div className={`p-3 text-xs rounded-lg ${message.type === 'success' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'}`}>
              {message.text}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:opacity-50 text-white font-semibold rounded-lg transition-colors shadow-lg"
          >
            {loading ? 'Validando Cadena...' : 'Restablecer Acceso'}
          </button>
        </form>
      </div>
    </div>
  );
}