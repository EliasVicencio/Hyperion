import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, UserPlus, RefreshCw, CheckCircle, Clock, Trash2, Loader2 } from 'lucide-react';
import ModalCrearOperador from './ModalCrearOperador';
import { apiGet, apiDelete } from '../api';

export default function Operadores() {
    const [usuarios, setUsuarios] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [isModalOpen, setIsModalOpen] = useState(false);

    // --- NUEVO: Estado para rastrear qué operador se está eliminando actualmente ---
    const [eliminandoId, setEliminandoId] = useState(null);

    const cargarUsuarios = async () => {
        setLoading(true);
        setError(null);
        try {
            const response = await apiGet('/api/v1/operadores');
            if (!response.ok) throw new Error('Error al conectar con la base de datos de operadores');
            const data = await response.json();
            setUsuarios(data);
        } catch (err) {
            console.error(err);
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        cargarUsuarios();
    }, []);

    const handleUserCreated = () => {
        cargarUsuarios();
    };

    // --- Función corregida para eliminar usando la Clave Primaria (ID) ---
    const handleEliminarOperador = async (userId, userEmail) => {
        if (!userId) {
            alert(`⚠️ Error de consistencia: El operador con email ${userEmail} no tiene un ID válido en el frontend.`);
            return;
        }

        const confirmar = window.confirm(`¿Está seguro de que desea revocar el acceso y eliminar permanentemente al operador ${userEmail} (ID: ${userId})?`);
        if (!confirmar) return;

        setEliminandoId(userId);

        try {
            const response = await apiDelete(`/api/v1/operadores/${userId}`);

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || 'No se pudo eliminar el operador del perímetro.');
            }

            await cargarUsuarios();
        } catch (err) {
            console.error(err);
            alert(`⚠️ Error al eliminar operador: ${err.message}`);
        } finally {
            setEliminandoId(null);
        }
    };

    return (
        // 🌟 CAMBIO: Adaptado el texto base para heredar correctamente text-slate-800 en claro y dark:text-slate-200 en oscuro
        <div className="space-y-6 text-slate-800 dark:text-slate-200">
            {/* Encabezado */}
            <header className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-4">
                <div>
                    {/* 🌟 CAMBIO: Cambiado text-white a text-slate-900 dark:text-white */}
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
                        <Shield className="text-blue-500" size={28} /> Control de Operadores
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
                        Gestión de identidades con acceso al perímetro del SGSI (RBAC)
                    </p>
                </div>
                <div className="flex gap-3 w-full sm:w-auto justify-end">
                    {/* 🌟 CAMBIO: Botón de Sincronización adaptativo */}
                    <button
                        onClick={cargarUsuarios}
                        disabled={loading}
                        className="p-2.5 bg-white dark:bg-slate-900 text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-white border border-slate-200 dark:border-slate-800 rounded-xl transition-all disabled:opacity-50 shadow-sm hover:bg-slate-50 dark:hover:bg-slate-800"
                        title="Sincronizar base de datos"
                    >
                        <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
                    </button>

                    <button
                        onClick={() => setIsModalOpen(true)}
                        className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-4 py-2 rounded-xl text-sm flex items-center gap-2 transition-all shadow-lg shadow-blue-600/20"
                    >
                        <UserPlus size={16} /> Alta de Operador
                    </button>
                </div>
            </header>

            {/* Estado de Carga Inicial */}
            {/* 🌟 CAMBIO: Caja de Carga adaptativa */}
            {loading && usuarios.length === 0 && (
                <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 p-12 rounded-2xl text-center text-slate-500 dark:text-slate-400 italic shadow-sm">
                    <RefreshCw size={24} className="animate-spin mx-auto mb-3 text-blue-500" />
                    Consultando registros inmutables en PostgreSQL...
                </div>
            )}

            {/* Estado de Error */}
            {error && !loading && (
                <div className="bg-red-500/10 border border-red-500/20 p-5 rounded-2xl text-red-600 dark:text-red-400 flex items-start gap-3">
                    <ShieldAlert size={20} className="mt-0.5 shrink-0" />
                    <div>
                        <p className="font-semibold text-sm">Error de enlace perimetral</p>
                        <p className="text-xs opacity-80 mt-0.5">{error}. Verifica que el contenedor del backend esté operativo.</p>
                    </div>
                </div>
            )}

            {/* Tabla de Usuarios */}
            {/* 🌟 CAMBIO: Contenedor y bordes de la tabla adaptativos */}
            {(!loading || usuarios.length > 0) && !error && (
                <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-900 rounded-2xl overflow-hidden shadow-sm dark:shadow-xl transition-colors">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            {/* 🌟 CAMBIO: Encabezado de la tabla modificado para modo claro */}
                            <thead className="bg-slate-50 dark:bg-slate-950/60 border-b border-slate-100 dark:border-slate-800/60 text-slate-500 dark:text-slate-400 uppercase text-[10px] tracking-widest font-semibold">
                                <tr>
                                    <th className="px-6 py-4">Operador / Identidad</th>
                                    <th className="px-6 py-4">Rol asignado</th>
                                    <th className="px-6 py-4">Estado de Cuenta</th>
                                    <th className="px-6 py-4">Última Auditoría</th>
                                    <th className="px-6 py-4 text-right">Acciones</th>
                                </tr>
                            </thead>
                            {/* 🌟 CAMBIO: Divisor adaptativo */}
                            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/40 text-xs sm:text-sm">
                                {usuarios.length > 0 ? (
                                    usuarios.map((user) => {
                                        const idActual = user.id || user.email;
                                        const estaEliminando = eliminandoId === idActual;

                                        return (
                                            /* 🌟 CAMBIO: Efecto hover suavizado para modo claro */
                                            <tr key={idActual} className="hover:bg-slate-50/80 dark:hover:bg-blue-500/[0.02] transition-colors">
                                                <td className="px-6 py-4">
                                                    <div className="flex flex-col">
                                                        {/* 🌟 CAMBIO: Texto del nombre adaptado */}
                                                        <span className="text-slate-800 dark:text-slate-200 font-medium">{user.nombre || 'Sin Nombre'}</span>
                                                        <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500 mt-0.5">{user.email}</span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4">
                                                    {/* 🌟 CAMBIO: Badge del Rol adaptado con mejores contrastes en claro */}
                                                    <span className="font-mono text-[11px] text-blue-600 dark:text-blue-400 font-bold bg-blue-50 dark:bg-blue-500/10 px-2 py-1 rounded-md border border-blue-100 dark:border-blue-500/20 uppercase">
                                                        {user.rol || 'OPERADOR'}
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4">
                                                    {/* 🌟 CAMBIO: Badge de Estado adaptado */}
                                                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wide border ${user.activo
                                                            ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-100 dark:border-emerald-500/20'
                                                            : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700'
                                                        }`}>
                                                        {user.activo ? <CheckCircle size={10} /> : <Clock size={10} />}
                                                        {user.activo ? 'ACTIVO' : 'SUSPENDIDO'}
                                                    </span>
                                                </td>
                                                {/* 🌟 CAMBIO: Color de texto de la última auditoría adaptado */}
                                                <td className="px-6 py-4 text-slate-600 dark:text-slate-400 font-mono text-xs">
                                                    {user.ultima_conexion || 'Nunca'}
                                                </td>
                                                <td className="px-6 py-4 text-right">
                                                    {/* 🌟 CAMBIO: Botón de eliminación adaptado con bordes limpios en claro */}
                                                    <button
                                                        onClick={() => handleEliminarOperador(user.id, user.email)}
                                                        disabled={estaEliminando || loading}
                                                        className="p-2 bg-slate-50 dark:bg-slate-950/40 hover:bg-red-50 dark:hover:bg-red-500/10 text-slate-400 dark:text-slate-500 hover:text-red-500 dark:hover:text-red-400 border border-slate-200 dark:border-slate-900 hover:border-red-200 dark:hover:border-red-500/20 rounded-xl transition-all disabled:opacity-40"
                                                        title="Revocar credenciales de operador"
                                                    >
                                                        {estaEliminando ? (
                                                            <Loader2 size={14} className="animate-spin text-red-500 dark:text-red-400" />
                                                        ) : (
                                                            <Trash2 size={14} />
                                                        )}
                                                    </button>
                                                </td>
                                            </tr>
                                        );
                                    })
                                ) : (
                                    <tr>
                                        {/* 🌟 CAMBIO: Celda vacía adaptativa */}
                                        <td colSpan="5" className="px-6 py-12 text-center text-slate-400 dark:text-slate-500 italic">
                                            No hay operadores registrados en la base de datos.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            <ModalCrearOperador
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                onUserCreated={handleUserCreated}
            />
        </div>
    );
}