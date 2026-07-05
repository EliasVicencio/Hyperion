import React, { useState, useEffect } from 'react';
import ConfiguracionFlotante from './components/ConfiguracionFlotante';

function App() {
  // --- Estados de Interfaz y Control ---
  const [isConfigOpen, setIsConfigOpen] = useState(false);
  const [operadores, setOperadores] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorConexion, setErrorConexion] = useState(false);
  const [lastSync, setLastSync] = useState(null);

  // --- Función de Sincronización (Usando tu Proxy del Frontend) ---
  const fetchOperadores = async () => {
    setLoading(true);
    setErrorConexion(false);
    try {
      // Apunta a tu ruta proxy interna configurada en el frontend
      const response = await fetch('/api/v1/operadores');
      if (!response.ok) throw new Error('Fallo en la respuesta del nodo');
      
      const data = await response.json();
      setOperadores(data);
      setLastSync(new Date().toLocaleTimeString());
    } catch (err) {
      console.error('Error al sincronizar con el perímetro:', err);
      setErrorConexion(true);
    } finally {
      setLoading(false);
    }
  };

  // Carga inicial al montar el componente
  useEffect(() => {
    fetchOperadores();
  }, []);

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans overflow-hidden">
      
      {/* 1. BARRA LATERAL (SIDEBAR) */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between p-4">
        <div className="space-y-6">
          <div className="flex items-center gap-3 px-2">
            <div className="h-8 w-8 rounded-lg bg-blue-600 flex items-center justify-center font-bold text-white shadow-lg shadow-blue-500/20">
              Η
            </div>
            <div>
              <h1 className="text-md font-bold tracking-wider text-white">HYPERION</h1>
              <p className="text-[10px] text-slate-500 font-mono">CORE SYSTEM v2.0</p>
            </div>
          </div>

          <nav className="space-y-1">
            <button className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg bg-slate-800 text-blue-400 border border-slate-700/50">
              📊 Monitorización
            </button>
            <button className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 transition-colors">
              🛡️ Cortafuegos SGSI
            </button>
            <button className="w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 transition-colors">
              📜 Logs de Auditoría
            </button>
          </nav>
        </div>

        {/* BOTÓN DE AJUSTES INTEGRADO EN LA BASE DEL SIDEBAR */}
        <div className="border-t border-slate-800 pt-4">
          <button 
            onClick={() => setIsConfigOpen(true)}
            className="w-full flex items-center justify-between px-3 py-2.5 text-sm font-medium rounded-xl bg-slate-800/40 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-slate-700 transition-all group"
          >
            <div className="flex items-center gap-3">
              <span className="text-lg group-hover:rotate-45 transition-transform duration-300">⚙️</span>
              <span>Ajustes de Perfil</span>
            </div>
            <span className="text-xs bg-slate-700 px-1.5 py-0.5 rounded text-slate-400 font-mono">2FA</span>
          </button>
        </div>
      </aside>

      {/* 2. ÁREA DE CONTENIDO PRINCIPAL */}
      <main className="flex-1 flex flex-col bg-slate-950 overflow-y-auto">
        
        {/* CABECERA TOPBAR */}
        <header className="h-16 border-b border-slate-800 px-8 flex items-center justify-between bg-slate-900/40 backdrop-blur-md sticky top-0 z-10">
          <div className="flex items-center gap-4">
            <h2 className="text-lg font-bold text-white">Panel de Control de Operadores</h2>
            {lastSync && (
              <span className="text-xs text-slate-500 font-mono">Última sinc: {lastSync}</span>
            )}
          </div>
          
          <button 
            onClick={fetchOperadores}
            disabled={loading}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white font-medium text-sm px-4 py-2 rounded-xl transition-colors shadow-lg shadow-blue-600/10 active:scale-98"
          >
            {loading ? 'Sincronizando...' : '🔄 Sincronizar'}
          </button>
        </header>

        {/* CUERPO DEL DASHBOARD */}
        <div className="p-8 space-y-6 max-w-7xl w-full mx-auto">
          
          {/* BANNER DE ADVERTENCIA / ALERTA SI EL ENLACE FALLA */}
          {errorConexion && (
            <div className="bg-red-950/40 border border-red-800/60 rounded-2xl p-4 flex items-start gap-3 text-red-300 animate-fade-in">
              <span className="text-xl">⚠️</span>
              <div>
                <h4 className="text-sm font-bold text-white">Fallo de Enlace Perimetral</h4>
                <p className="text-xs text-red-400/90 mt-0.5">
                  El frontend proxy no pudo resolver la comunicación con el microservicio. Se están sirviendo credenciales estáticas locales de contingencia.
                </p>
              </div>
            </div>
          )}

          {/* TABLA DE OPERADORES REGISTRADOS (SUPABASE) */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <div className="p-5 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white">Nodos Operadores Activos</h3>
                <p className="text-xs text-slate-400">Identidades verificadas en la base de datos perimetral</p>
              </div>
              <span className="text-xs font-mono bg-slate-800 px-2.5 py-1 rounded-full border border-slate-700 text-slate-300">
                Total: {operadores.length}
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 text-xs uppercase tracking-wider font-semibold bg-slate-950/40">
                    <th className="py-3 px-5">ID</th>
                    <th className="py-3 px-5">Nombre / Operador</th>
                    <th className="py-3 px-5">Correo Electrónico</th>
                    <th className="py-3 px-5">Rol Asignado</th>
                    <th className="py-3 px-5">Última Conexión</th>
                    <th className="py-3 px-5 text-right">Estado</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {operadores.map((op) => (
                    <tr key={op.id} className="hover:bg-slate-800/30 transition-colors group">
                      <td className="py-3.5 px-5 font-mono text-xs text-slate-500">#{op.id}</td>
                      <td className="py-3.5 px-5 font-medium text-white group-hover:text-blue-400 transition-colors">{op.nombre}</td>
                      <td className="py-3.5 px-5 text-slate-300">{op.email}</td>
                      <td className="py-3.5 px-5">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium ${op.rol.includes('ADMIN') ? 'bg-purple-950 text-purple-300 border border-purple-800/50' : 'bg-slate-800 text-slate-300 border border-slate-700'}`}>
                          {op.rol}
                        </span>
                      </td>
                      <td className="py-3.5 px-5 font-mono text-xs text-slate-400">{op.ultima_conexion}</td>
                      <td className="py-3.5 px-5 text-right">
                        <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded-full border border-emerald-900/50 font-medium">
                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                          Online
                        </span>
                      </td>
                    </tr>
                  ))}
                  {operadores.length === 0 && !loading && (
                    <tr>
                      <td colSpan="6" className="py-8 text-center text-slate-500 text-xs">
                        No hay operadores cargados en el nodo. Haz clic en Sincronizar.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      </main>

      {/* 3. INYECCIÓN DEL MODAL FLOTANTE DE CONFIGURACIÓN */}
      <ConfiguracionFlotante 
        isOpen={isConfigOpen} 
        onClose={() => setIsConfigOpen(false)} 
      />

    </div>
  );
}

export default App;