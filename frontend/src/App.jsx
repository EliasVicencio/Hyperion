import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Operadores from './pages/Operadores';
import Vigilancia from './pages/Vigilancia';
import Gobernanza from './pages/Gobernanza';
import Logs from './pages/Logs';
import Login from './pages/Login'; 
import Academia from './pages/Academia';
import ConfiguracionFlotante from './components/ConfiguracionFlotante'; 
import { AnimatePresence, motion } from 'framer-motion';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    return localStorage.getItem('hyperion_auth') === 'true';
  });
  
  const [page, setPage] = useState('Analiticas');
  const [isConfigOpen, setIsConfigOpen] = useState(false);

  // 🌟 NUEVO: Estado global para almacenar el objeto de usuario verificado
  const [currentUser, setCurrentUser] = useState(() => {
    const saved = localStorage.getItem('hyperion_user');
    try {
      return saved ? JSON.parse(saved) : null;
    } catch (e) {
      console.error("Error parseando usuario inicial:", e);
      return null;
    }
  });

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, []);

  const handleLoginSuccess = (userData) => {
    localStorage.setItem('hyperion_auth', 'true');
    localStorage.setItem('hyperion_user', JSON.stringify(userData));
    setCurrentUser(userData); // Guardar de inmediato en el estado de React
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('hyperion_auth');
    localStorage.removeItem('hyperion_user');
    setCurrentUser(null);
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  const renderPage = () => {
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
      case 'gestion de usuarios': 
        return <Operadores />;
      case 'gobernanza':
        return <Gobernanza />;
      case 'logs':
      case 'logs de auditoria':   
        return <Logs />;
      case 'academia':
      case 'academia compliance': 
        // 🌟 CORREGIDO: Le inyectamos el usuario verificado directamente como Prop 
        // para que la Academia no dependa de lecturas asíncronas del localStorage
        return <Academia user={currentUser} />;
      default:
        return (
          <div className="h-[60vh] flex items-center justify-center border border-dashed dark:border-slate-800 border-slate-300 rounded-3xl">
              <p className="dark:text-slate-500 text-slate-400 italic">Módulo {page} en fase de despliegue...</p>
          </div>
        );
    }
  };

  return (
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
              key={page} // Mantiene la animación limpia entre cambios de módulos
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

      <ConfiguracionFlotante 
        isOpen={isConfigOpen} 
        onClose={() => setIsConfigOpen(false)} 
      />
    </div>
  );
}