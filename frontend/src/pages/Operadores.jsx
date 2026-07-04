import React, { useState } from 'react';
import { Search, UserPlus, MoreHorizontal, ShieldCheck, Mail } from 'lucide-react';

export default function Operadores() {
  const [search, setSearch] = useState('');

  const users = [
    { id: 1, name: "Elias Vicencio", email: "admin@hyperion.ops", role: "Admin", status: "Activo" },
    { id: 2, name: "Operador Alpha", email: "alpha@hyperion.ops", role: "User", status: "Activo" },
  ];

  return (
    <div className="space-y-6">
      <header className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-white">Gestión de Usuarios</h1>
          <p className="text-slate-500 text-sm">Control de acceso basado en roles (RBAC)</p>
        </div>
        <button className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all shadow-lg shadow-blue-600/20">
          <UserPlus size={18} /> Nuevo Usuario
        </button>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Tabla Principal */}
        <div className="lg:col-span-3 bg-hyperion-card border border-slate-800/50 rounded-3xl overflow-hidden shadow-2xl">
            <div className="p-4 border-b border-slate-800/50 bg-slate-900/20">
                <div className="relative">
                    <Search className="absolute left-3 top-2.5 text-slate-500" size={18} />
                    <input 
                        type="text" 
                        placeholder="Filtrar por nombre, correo o rol..." 
                        className="bg-slate-950 border border-slate-800 rounded-xl py-2 pl-10 pr-4 w-full text-sm focus:border-blue-500 outline-none transition-all"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>
            </div>
            <table className="w-full text-left text-sm">
                <thead className="bg-slate-950/50 text-slate-500 uppercase text-[10px] tracking-widest">
                    <tr>
                        <th className="px-6 py-4">Usuario</th>
                        <th className="px-6 py-4">Rol</th>
                        <th className="px-6 py-4">Estado</th>
                        <th className="px-6 py-4 text-right">Acciones</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                    {users.map(user => (
                        <tr key={user.id} className="hover:bg-blue-500/[0.02] transition-colors group">
                            <td className="px-6 py-4">
                                <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 rounded-full flex items-center justify-center font-bold text-blue-400 shadow-inner">
                                        {user.name.charAt(0)}
                                    </div>
                                    <div className="flex flex-col">
                                        <span className="text-slate-200 font-medium">{user.name}</span>
                                        <span className="text-slate-500 text-xs">{user.email}</span>
                                    </div>
                                </div>
                            </td>
                            <td className="px-6 py-4">
                                <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-tighter ${
                                    user.role === 'Admin' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                                }`}>
                                    {user.role}
                                </span>
                            </td>
                            <td className="px-6 py-4">
                                <div className="flex items-center gap-2 text-emerald-400 text-xs font-medium">
                                    <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full shadow-[0_0_8px_rgba(16,185,129,0.5)]"></span>
                                    {user.status}
                                </div>
                            </td>
                            <td className="px-6 py-4 text-right">
                                <button className="text-slate-600 hover:text-white transition-colors">
                                    <MoreHorizontal size={20} />
                                </button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>

        {/* Sidebar Informativo */}
        <div className="space-y-6">
            <div className="bg-gradient-to-b from-blue-600/20 to-transparent p-6 border border-blue-500/20 rounded-3xl relative overflow-hidden group">
                <ShieldCheck className="absolute -right-4 -top-4 text-blue-500/10 group-hover:scale-110 transition-transform duration-700" size={120} />
                <h3 className="text-blue-400 font-bold text-sm mb-2 uppercase tracking-tight">Privilegios del Sistema</h3>
                <p className="text-slate-400 text-xs leading-relaxed mb-4">
                    Los administradores pueden revocar accesos en tiempo real mediante el protocolo SIEM-Audit.
                </p>
                <div className="space-y-2">
                    <div className="flex items-center gap-2 text-[11px] text-slate-300 bg-slate-950/50 p-2 rounded-lg border border-slate-800">
                        <Mail size={14} className="text-blue-500" /> Notificaciones 2FA activas
                    </div>
                </div>
            </div>
        </div>
      </div>
    </div>
  );
}