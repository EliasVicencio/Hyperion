import React from 'react';
import { LayoutDashboard, Shield, ShieldAlert, FileText, Settings, LogOut, Zap } from 'lucide-react';

export default function Sidebar({ currentPage, setPage, onLogout, onOpenConfig, isConfigOpen }) { // 👈 1. Recibe aquí las props de configuración
  const menu = [
    { id: 'Analiticas', label: 'Analíticas', icon: <LayoutDashboard size={18} /> },
    { id: 'Vigilancia', label: 'Vigilancia', icon: <ShieldAlert size={18} /> },
    { id: 'Operadores', label: 'Gestión de Usuarios', icon: <Shield size={18} /> },
    { id: 'Gobernanza', label: 'Gobernanza', icon: <Zap size={18} /> },
    { id: 'Logs', label: 'Logs de Auditoría', icon: <FileText size={18} /> },
  ];

  return (
    <div className="w-64 h-screen bg-[#050810] border-r border-slate-900/50 flex flex-col fixed left-0 top-0 z-50">
      <div className="p-6">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center shadow-lg shadow-blue-500/20">
            <Shield className="text-white" size={20} />
          </div>
          <span className="font-bold text-lg tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
            HYPERION CORE
          </span>
        </div>

        <nav className="space-y-1">
          {/* Renderizado de las secciones principales del menú */}
          {menu.map((item) => (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all group ${
                currentPage === item.id
                  ? 'bg-blue-600/10 text-blue-400 border border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.1)]'
                  : 'text-slate-500 hover:bg-slate-900 hover:text-slate-200 border border-transparent'
              }`}
            >
              <span className={currentPage === item.id ? 'text-blue-400' : 'text-slate-600 group-hover:text-slate-400'}>
                {item.icon}
              </span>
              {item.label}
            </button>
          ))}

          {/* 👈 2. BOTÓN DE CONFIGURACIÓN FUERA DEL MAP (Se mantiene como opción independiente) */}
          <button
            onClick={onOpenConfig}
            className={`w-full flex items-center justify-between px-4 py-3 rounded-xl text-sm font-medium transition-all group border ${
              isConfigOpen
                ? 'bg-blue-600/10 text-blue-400 border-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.1)]'
                : 'text-slate-500 hover:bg-slate-900 hover:text-slate-200 border border-transparent'
            }`}
          >
            <div className="flex items-center gap-3">
              <span className={isConfigOpen ? 'text-blue-400' : 'text-slate-600 group-hover:text-slate-400'}>
                <Settings size={18} />
              </span>
              <span>Configuración</span>
            </div>
            <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono transition-colors ${
              isConfigOpen ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-900 text-slate-500 group-hover:text-slate-400'
            }`}>
              2FA
            </span>
          </button>
        </nav>
      </div>

      <div className="mt-auto p-6 border-t border-slate-900/50">
        <button
          onClick={onLogout}
          className="flex items-center gap-3 text-slate-500 hover:text-red-400 text-sm font-medium w-full transition-colors group"
        >
          <LogOut size={18} className="text-slate-600 group-hover:text-red-400 transition-colors" />
          Cerrar Sistema
        </button>
      </div>
    </div>
  );
}