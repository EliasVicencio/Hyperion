import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Operadores from './pages/Operadores';
import Vigilancia from './pages/Vigilancia';
import Gobernanza from './pages/Gobernanza';
import Logs from './pages/Logs';
import Login from './pages/Login'; // Importa la pantalla de Login
import ConfiguracionFlotante from './components/ConfiguracionFlotante'; // Importamos la pestaña flotante
import { AnimatePresence, motion } from 'framer-motion';

export default function App() {
  // Estado para controlar si el operador tiene acceso o no
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [page, setPage] = useState('Analiticas');
  
  // Estado global para controlar si la pestaña de configuración está abierta o no
  const [isConfigOpen, setIsConfigOpen] = useState(false);

  // --- NUEVO: Efecto inicial para sincronizar el tema de Tailwind al cargar la app ---
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    // Si estaba guardado oscuro, o si es la primera vez y el sistema prefiere oscuro
    if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, []);

  // Si no está autenticado, renderizamos ÚNICAMENTE la pantalla de Login
  if (!isAuthenticated) {
    return <Login onLoginSuccess={() => setIsAuthenticated(true)} />;
  }

  const renderPage = () => {
    switch (page) {
      case 'Analiticas': return <Dashboard />;
      case 'Vigilancia': return <Vigilancia />;
      case 'Operadores': return <Operadores />;
      case 'Gobernanza': return <Gobernanza />;
      case 'Logs':       return <Logs />;
      default:
        return (
          // Modificado: Ahora el contenedor vacío también responde al modo claro/oscuro
          <div className="h-[60vh] flex items-center justify-center border border-dashed dark:border-slate-800 border-slate-300 rounded-3xl">
              <p className="dark:text-slate-500 text-slate-400 italic">Módulo {page} en fase de despliegue...</p>
          </div>
        );
    }
  };

  return (
    // ☀️ Modo Claro: bg-hyperion-lightBg, text-slate-800
    // 🌙 Modo Oscuro: dark:bg-hyperion-dark, dark:text-slate-200
    <div className="min-h-screen bg-hyperion-lightBg dark:bg-hyperion-dark text-slate-800 dark:text-slate-200 flex font-sans selection:bg-blue-500/30 transition-colors duration-300">
      
      <Sidebar 
        currentPage={page} 
        setPage={setPage} 
        onLogout={() => setIsAuthenticated(false)} 
        onOpenConfig={() => setIsConfigOpen(true)} 
        isConfigOpen={isConfigOpen}
      />
      
      <main className="flex-1 ml-64 min-h-screen relative">
        <div className="p-8 max-w-7xl mx-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={page}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              {renderPage()}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>

      {/* Insertamos el componente flotante pasándole el estado y la función de cierre */}
      <ConfiguracionFlotante 
        isOpen={isConfigOpen} 
        onClose={() => setIsConfigOpen(false)} 
      />
    </div>
  );
}