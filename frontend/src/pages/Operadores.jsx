import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, UserPlus, RefreshCw, CheckCircle, Clock } from 'lucide-react';

export default function Operadores() {
    const [usuarios, setUsuarios] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Función para obtener los usuarios de la base de datos a través del backend
    const cargarUsuarios = async () => {
        setLoading(true);
        setError(null);
        try {
            // Usamos la ruta relativa gracias al proxy de Nginx / Vercel
            const baseUrl = import.meta.env.VITE_API_URL || '';
            const response = await fetch(`${baseUrl}/api/v1/operadores`);
            if (!response.ok) {
                throw new Error('Error al conectar con la base de datos de operadores');
            }
            const data = await response.json();
            setUsuarios(data);
        } catch (err) {
            console.error(err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    // Cargar automáticamente al montar el componente
    useEffect(() => {
        cargarUsuarios();
    }, []);

    return (
        <div className="space-y-6">
            {/* Encabezado */}
            <header className="flex justify-between items-end">
                <div>
                    <h1 className="text-3xl font-bold text-white tracking-tight flex items-center gap-3">
                        <Shield className="text-blue-500" size={28} /> Control de Operadores
                    </h1>
                    <p className="text-slate-500 text-sm">Gestión de identidades con acceso al perímetro del SGSI (RBAC)</p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={cargarUsuarios}
                        className="p-2.5 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 rounded-xl transition-all"
                        title="Sincronizar base de datos"
                    >
                        <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
                    </button>
                    <button className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-4 py-2 rounded-xl text-sm flex items-center gap-2 transition-all shadow-lg shadow-blue-600/10">
                        <UserPlus size={16} /> Alta de Operador
                    </button>
                </div>
            </header>

            {/* Estados de Carga y Error */}
            {loading && (
                <div className="bg-hyperion-card border border-slate-800/50 p-12 rounded-3xl text-center text-slate-400 italic">
                    <RefreshCw size={24} className="animate-spin mx-auto mb-3 text-blue-500" />
                    Consultando registros inmutables en PostgreSQL...
                </div>
            )}

            {error && (
                <div className="bg-red-500/10 border border-red-500/20 p-6 rounded-3xl text-red-400 flex items-center gap-3">
                    <ShieldAlert size={20} />
                    <div>
                        <p className="font-semibold">Error de enlace perimetral</p>
                        <p className="text-xs opacity-80">{error}. Verifica que el contenedor del backend esté operativo.</p>
                    </div>
                </div>
            )}

            {/* Tabla de Usuarios vinculada a la DB */}
            {!loading && !error && (
                <div className="bg-hyperion-card border border-slate-800/50 rounded-3xl overflow-hidden shadow-2xl">
                    <table className="w-full text-left text-sm">
                        <thead className="bg-slate-950/50 text-slate-500 uppercase text-[10px] tracking-widest">
                            <tr>
                                <th className="px-6 py-4">Operador / Identidad</th>
                                <th className="px-6 py-4">Rol asignado</th>
                                <th className="px-6 py-4">Estado de Cuenta</th>
                                <th className="px-6 py-4">Última Auditoría</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/40 text-xs md:text-sm">
                            {usuarios.length > 0 ? (
                                usuarios.map((user) => (
                                    <tr key={user.id || user.email} className="hover:bg-blue-500/[0.01] transition-colors">
                                        <td className="px-6 py-4">
                                            <div className="flex flex-col">
                                                <span className="text-slate-200 font-medium">{user.nombre || 'Sin Nombre'}</span>
                                                <span className="text-[10px] font-mono text-slate-500">{user.email}</span>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className="font-mono text-xs text-blue-400 font-bold bg-blue-500/5 px-2 py-1 rounded-md border border-blue-500/10">
                                                {user.rol || 'OPERADOR'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-semibold tracking-wide ${user.activo
                                                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                                    : 'bg-red-500/10 text-red-400 border border-red-500/20'
                                                }`}>
                                                {user.activo ? <CheckCircle size={10} /> : <Clock size={10} />}
                                                {user.activo ? 'ACTIVO' : 'SUSPENDIDO'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-slate-500 font-mono text-xs">
                                            {user.ultima_conexion || 'Nunca'}
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="4" className="px-6 py-12 text-center text-slate-500 italic">
                                        No hay operadores registrados en la base de datos.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}