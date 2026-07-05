import React from 'react';
import { LayoutDashboard, Shield, ShieldAlert, FileText, Settings, LogOut, Zap } from 'lucide-react';

export default function Sidebar({ currentPage, setPage, onLogout, onOpenConfig, isConfigOpen }) {
  const menu = [
    { id: 'Analiticas', label: 'Analíticas', icon: <LayoutDashboard size={18} /> },
    { id: 'Vigilancia', label: 'Vigilancia', icon: <ShieldAlert size={18} /> },
    { id: 'Operadores', label: 'Gestión de Usuarios', icon: <Shield size={18} /> },
    { id: 'Gobernanza', label: 'Gobernanza', icon: <Zap size={18} /> },
    { id: 'Logs', label: 'Logs de Auditoría', icon: <FileText size={18} /> },
  ];

  return (
    <div className="w-64 h-screen bg-[#050810] border-r border-slate-900/60 flex flex-col fixed left-0 top-0 z-50 select-none">
      
      {/* Sección Superior: Marca / Logo */}
      <div className="p-6">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-lg flex items-center justify-center shadow-lg shadow-blue-500/10">
            <Shield className="text-white" size={18} />
          </div>
          <span className="font-bold text-sm tracking-widest text-white">
            HYPERION CORE
          </span>
        </div>

        {/* Listado de Rutas / Páginas */}
        <nav className="space-y-1">
          {menu.map((item) => {
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setPage(item.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-xs sm:text-sm font-medium transition-all border ${
                  isActive
                    ? 'bg-blue-600/10 text-blue-400 border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.05)]'
                    : 'text-slate-500 hover:bg-slate-900/60 hover:text-slate-200 border-transparent'
                }`}
              >
                <span className={isActive ? 'text-blue-400' : 'text-slate-600 transition-colors'}>
                  {item.icon}
                </span>
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Sección Inferior: Ajustes y Cierre de Sesión */}
      <div className="mt-auto p-6 border-t border-slate-900/60 space-y-3.5">
        
        {/* Botón de Configuración Flotante */}
        <button
          onClick={onOpenConfig}
          className={`w-full flex items-center justify-between px-4 py-3 rounded-xl text-xs sm:text-sm font-medium transition-all border ${
            isConfigOpen
              ? 'bg-blue-600/10 text-blue-400 border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.05)]'
              : 'text-slate-500 hover:bg-slate-900/60 hover:text-slate-200 border-transparent'
          }`}
        >
          <div className="flex items-center gap-3">
            <span className={isConfigOpen ? 'text-blue-400' : 'text-slate-600'}>
              <Settings size={18} />
            </span>
            <span>Configuración</span>
          </div>
          <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold tracking-wide transition-colors ${
            isConfigOpen ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-900 text-slate-500'
          }`}>
            2FA
          </span>
        </button>

        {/* Botón Desconexión */}
        <button
          onClick={onLogout}
          className="flex items-center gap-3 text-slate-500 hover:text-red-400 text-xs sm:text-sm font-medium w-full px-4 py-2 transition-colors group"
        >
          <LogOut size={18} className="text-slate-600 group-hover:text-red-400 transition-colors" />
          Cerrar Sistema
        </button>
      </div>
    </div>
  );
}