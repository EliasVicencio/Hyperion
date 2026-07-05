import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Operadores from './pages/Operadores';
import Vigilancia from './pages/Vigilancia';
import Gobernanza from './pages/Gobernanza';
import Logs from './pages/Logs';
import Login from './pages/Login'; // Importa la pantalla de Login
import Academia from './pages/Academia';
import ConfiguracionFlotante from './components/ConfiguracionFlotante'; // Importamos la pestaña flotante
import { AnimatePresence, motion } from 'framer-motion';

export default function App() {
  // --- MODIFICADO: Estado inicial busca persistencia en localStorage para evitar logout al recargar ---
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return localStorage.getItem('hyperion_auth') === 'true';
  });
  
  const [page, setPage] = useState('Analiticas');
  
  // Estado global para controlar si la pestaña de configuración está abierta o no
  const [isConfigOpen, setIsConfigOpen] = useState(false);

  // --- Efecto inicial para sincronizar el tema de Tailwind al cargar la app ---
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, []);

  // --- NUEVO: Manejador de éxito en la autenticación ---
  const handleLoginSuccess = (userData) => {
    localStorage.setItem('hyperion_auth', 'true');
    localStorage.setItem('hyperion_user', JSON.stringify(userData));
    setIsAuthenticated(true);
  };

  // --- NUEVO: Manejador de cierre de sesión seguro ---
  const handleLogout = () => {
    localStorage.removeItem('hyperion_auth');
    localStorage.removeItem('hyperion_user');
    setIsAuthenticated(false);
  };

  // Si no está autenticado, renderizamos ÚNICAMENTE la pantalla de Login
  if (!isAuthenticated) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  // --- CORREGIDO: Mapeo tolerante a variaciones de nombres mediante normalización ---
  const renderPage = () => {
    // Convierte a minúsculas, remueve acentos/diacríticos y limpia espacios extra
    const normalizedPage = page
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .trim();

    switch (normalizedPage) {
      case 'analiticas':
      case 'dashboard':
        return <Dashboard />;
      case 'vigilancia':
        return <Vigilancia />;
      case 'operadores':
      case 'gestion de usuarios': // Mapea el texto exacto de tu Sidebar
        return <Operadores />;
      case 'gobernanza':
        return <Gobernanza />;
      case 'logs':
      case 'logs de auditoria':   // Mapea el texto exacto de tu Sidebar
        return <Logs />;
      case 'academia':
      case 'academia compliance': // Mapea el texto exacto de tu Sidebar
        return <Academia />;
      default:
        return (
          <div className="h-[60vh] flex items-center justify-center border border-dashed dark:border-slate-800 border-slate-300 rounded-3xl">
              <p className="dark:text-slate-500 text-slate-400 italic">Módulo {page} en fase de despliegue...</p>
          </div>
        );
    }
  };

  return (
    // ☀️ Modo Claro: bg-hyperion-lightBg, text-slate-800
    // 🌙 Modo Oscuro: dark:bg-hyperion-dark, dark:text-slate-200
    // 🛡️ Agregados bg-slate-50 y dark:bg-slate-950 como salvaguardas nativas
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 bg-hyperion-lightBg dark:bg-hyperion-dark text-slate-800 dark:text-slate-200 flex font-sans selection:bg-blue-500/30 transition-colors duration-300">
      
      <Sidebar 
        currentPage={page} 
        setPage={setPage} 
        onLogout={handleLogout} 
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